package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

// Google's security event tokens (SEC-39): an iat at most this old and at most
// this far ahead of the clock, and a remembered id kept this long from the later
// of the iat and the time received.
const (
	securityEventMaxAge   = 24 * time.Hour
	securityEventMaxAhead = 5 * time.Minute
	// riscMaxBody limits the RISC configuration document (1 MB, as the keys).
	riscMaxBody = 1 << 20
	// riscDrainLimit is how much of a failed RISC answer is read before the
	// connection is closed.
	riscDrainLimit = 1 << 16
)

// riscConfig is Google's RISC configuration document and the key set it names.
// It is read at the first event and kept; a read that fails is not kept, so the
// next event reads it again.
type riscConfig struct {
	url    string
	client *http.Client
	mu     sync.Mutex // guards issuer and keys; held while the document is read
	issuer string
	keys   *jwksKeys // nil until the document has been read
}

// riscDocument is the part of the RISC configuration document the service uses.
type riscDocument struct {
	Issuer  *string `json:"issuer"` // nil when the document has none; an empty one is kept
	JWKSURI string  `json:"jwks_uri"`
}

// load returns the issuer of the security event tokens and their key set,
// reading the document first when it has not been read. Every failure to read
// it is ErrUnavailable.
func (r *riscConfig) load(ctx context.Context) (string, *jwksKeys, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keys != nil {
		return r.issuer, r.keys, nil
	}
	doc, err := r.fetch(ctx)
	if err != nil {
		return "", nil, err
	}
	r.issuer = *doc.Issuer
	r.keys = &jwksKeys{url: doc.JWKSURI, client: r.client}
	return r.issuer, r.keys, nil
}

// fetch reads the document once. A redirect is not followed (the 3xx is the
// answer), and the body is limited; the answer is never put into an error.
func (r *riscConfig) fetch(ctx context.Context) (riscDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return riscDocument{}, fmt.Errorf("%w: the RISC configuration URL is not valid", ErrUnavailable)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return riscDocument{}, fmt.Errorf("%w: the RISC configuration could not be reached", ErrUnavailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, riscDrainLimit))
		return riscDocument{}, fmt.Errorf("%w: the RISC configuration answered %d", ErrUnavailable, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, riscMaxBody))
	if err != nil {
		return riscDocument{}, fmt.Errorf("%w: the RISC configuration could not be read", ErrUnavailable)
	}
	var doc riscDocument
	if err := json.Unmarshal(body, &doc); err != nil || doc.Issuer == nil || doc.JWKSURI == "" {
		return riscDocument{}, fmt.Errorf("%w: the RISC configuration has no issuer or keys", ErrUnavailable)
	}
	return doc, nil
}

// ParseEvent implements EventReceiver for Google's security event tokens
// (Google Cross-Account Protection). body is the token itself. It is verified
// with the keys of the RISC configuration, RS256 only; its issuer must equal the
// configuration's issuer or differ from it by one trailing slash (sameIssuer)
// and its aud must hold our client id; its iat is at most 24 hours old and at
// most 5 minutes ahead, and it needs a jti. Each member of its events claim is
// one event: its type is the last part of the member's name, and its subject is
// set only for an iss-sub subject with the configuration's issuer (by the same
// rule). Every event shares the jti as its ID and the later of
// the iat and now plus 24 hours as its expiry (SEC-27).
//
// A token whose keys cannot be fetched or whose RISC configuration cannot be
// read is ErrUnavailable; every other failure is ErrInvalidEvent.
func (g *Google) ParseEvent(ctx context.Context, body []byte) ([]Event, error) {
	invalid := func(why string) ([]Event, error) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidEvent, why)
	}
	issuer, keys, err := g.risc.load(ctx)
	if err != nil {
		return nil, err
	}
	vctx, kf := withKeyFetch(ctx)
	// The issuer is compared here, exactly: go-oidc would also accept the
	// variant of Google's issuer without a scheme.
	v := gooidc.NewVerifier(issuer, keys, &gooidc.Config{
		SkipClientIDCheck: true, SkipExpiryCheck: true, SkipIssuerCheck: true,
		SupportedSigningAlgs: []string{"RS256"}, Now: g.clock.Now,
	})
	idt, err := v.Verify(vctx, string(body))
	if err != nil {
		if kf.failed {
			return nil, fmt.Errorf("%w: the provider's keys could not be fetched", ErrUnavailable)
		}
		return invalid("the token is not valid")
	}
	if !sameIssuer(idt.Issuer, issuer) {
		return invalid("the token is from another issuer")
	}
	if !slices.Contains(idt.Audience, g.oauth.ClientID) {
		return invalid("the token is for another audience")
	}
	var claims struct {
		Events json.RawMessage `json:"events"`
		Iat    *json.Number    `json:"iat"`
		Jti    string          `json:"jti"`
	}
	if err := idt.Claims(&claims); err != nil {
		return invalid("the token claims are not valid")
	}
	if claims.Jti == "" {
		return invalid("the token has no jti")
	}
	if claims.Iat == nil {
		return invalid("the token has no iat")
	}
	iat, err := numericDate(claims.Iat)
	if err != nil {
		return invalid("the token's iat is not a time")
	}
	now := g.clock.Now()
	if now.Sub(iat) > securityEventMaxAge || iat.Sub(now) > securityEventMaxAhead {
		return invalid("the token was issued more than 24 hours ago or more than 5 minutes ahead")
	}
	events, err := securityEvents(claims.Events, issuer)
	if err != nil {
		return nil, err
	}
	from := now
	if iat.After(now) {
		from = iat
	}
	expires := from.Add(securityEventMaxAge)
	for i := range events {
		events[i].ID = claims.Jti
		events[i].Expires = expires
	}
	return events, nil
}

// securityEvents reads the events claim: a JSON object whose members are JSON
// objects. Each member is one event (see ParseEvent); the subject is read from
// its subject object and the state from a verification event. The events come
// in the order of their names. Every failure wraps ErrInvalidEvent.
func securityEvents(raw json.RawMessage, issuer string) ([]Event, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, fmt.Errorf("%w: the events claim is not an object", ErrInvalidEvent)
	}
	var out []Event
	for _, name := range slices.Sorted(maps.Keys(members)) {
		val := bytes.TrimSpace(members[name])
		if len(val) == 0 || val[0] != '{' {
			return nil, fmt.Errorf("%w: event %q is not an object", ErrInvalidEvent, name)
		}
		var body struct {
			Subject *struct {
				SubjectType string `json:"subject_type"`
				Iss         string `json:"iss"`
				Sub         string `json:"sub"`
			} `json:"subject"`
			State string `json:"state"`
		}
		if err := json.Unmarshal(val, &body); err != nil {
			return nil, fmt.Errorf("%w: event %q is not valid: %w", ErrInvalidEvent, name, err)
		}
		ev := Event{Set: EventSetGoogle, Type: name[strings.LastIndex(name, "/")+1:]}
		if s := body.Subject; s != nil && s.SubjectType == "iss-sub" && sameIssuer(s.Iss, issuer) && s.Sub != "" {
			ev.Subject = s.Sub
		}
		if ev.Type == "verification" {
			ev.State = body.State
		}
		out = append(out, ev)
	}
	return out, nil
}

// sameIssuer is the issuer rule of the security events (FR-48): a and b match
// when each, after removing one trailing "/" if it has one, gives the same text,
// that text is not empty and does not itself end in "/". So two slashes never
// match, and an issuer that is empty, "/" or ends in "//" matches nothing.
// Nothing else is normalised, not the case, the scheme, a space or a path.
func sameIssuer(a, b string) bool {
	a, b = strings.TrimSuffix(a, "/"), strings.TrimSuffix(b, "/")
	return a == b && a != "" && !strings.HasSuffix(a, "/")
}
