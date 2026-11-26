package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// Apple's fixed issuer and endpoints.
const (
	AppleIssuer       = "https://appleid.apple.com"
	appleAuthorizeURL = "https://appleid.apple.com/auth/authorize"
	appleTokenURL     = "https://appleid.apple.com/auth/token"
	appleKeysURL      = "https://appleid.apple.com/auth/keys"
	appleRevokeURL    = "https://appleid.apple.com/auth/revoke"
)

// AppleOptions configures the Apple adapter. OIDCOptions.ClientID is the
// Services ID; Issuer and ClientSecret are ignored (the issuer is fixed and
// the client secret is generated); Endpoints and RevokeURL default to Apple's.
type AppleOptions struct {
	OIDCOptions
	TeamID            string
	KeyID             string
	PrivateKeyPEM     []byte
	Lifetime          time.Duration // of each generated client secret
	StoreRefreshToken bool
	RevokeURL         string
	// NotificationAudiences are the aud values of account events accepted
	// besides the client id.
	NotificationAudiences []string
}

// Apple is the Sign in with Apple adapter, built on OIDC.
type Apple struct {
	*OIDC
	store     bool
	secret    *AppleSecret
	revokeURL string
	audiences []string // of account events: the client id and notification_audiences
	clock     clock.Clock
}

var (
	_ Provider       = (*Apple)(nil)
	_ Revoker        = (*Apple)(nil)
	_ EventReceiver  = (*Apple)(nil)
	_ FormPoster     = (*Apple)(nil)
	_ slog.LogValuer = Apple{}
)

// LogValue implements slog.LogValuer. The adapter holds the private key, so
// only the name, team id and key id are logged.
func (a Apple) LogValue() slog.Value {
	return slog.GroupValue(slog.String("provider", a.name), slog.Any("signer", a.secret))
}

// NewApple builds the adapter. It makes no network call: Apple's endpoints
// are fixed.
func NewApple(ctx context.Context, o AppleOptions) (*Apple, error) {
	secret, err := NewAppleSecret(AppleSecretOptions{
		TeamID: o.TeamID, KeyID: o.KeyID, ServicesID: o.ClientID, PrivateKeyPEM: o.PrivateKeyPEM,
		Lifetime: o.Lifetime, Clock: o.Clock,
	})
	if err != nil {
		return nil, err
	}
	oo := o.OIDCOptions
	oo.Issuer = AppleIssuer
	oo.ClientSecret = ""
	oo.Endpoints.Userinfo = "" // Apple has no user-info endpoint
	if len(oo.Algorithms) == 0 {
		oo.Algorithms = []string{"RS256"} // what Apple signs ID tokens with
	}
	for _, e := range []struct {
		dst *string
		def string
	}{
		{&oo.Endpoints.Authorize, appleAuthorizeURL}, {&oo.Endpoints.Token, appleTokenURL}, {&oo.Endpoints.JWKS, appleKeysURL},
	} {
		if *e.dst == "" {
			*e.dst = e.def
		}
	}
	p, err := NewOIDC(ctx, oo)
	if err != nil {
		return nil, err
	}
	p.name = "apple"
	// Apple's web sign-in always asks the user to confirm, so no hint is passed.
	p.hints = func(AuthOptions) url.Values { return url.Values{} }
	p.extra = url.Values{"response_mode": {"form_post"}}
	p.noPKCE = true
	p.secret = secret.Secret
	p.verified = appleBool
	// Apple takes the client credentials in the form.
	p.oauth.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	a := &Apple{OIDC: p, store: o.StoreRefreshToken, secret: secret, revokeURL: o.RevokeURL,
		audiences: append([]string{o.ClientID}, o.NotificationAudiences...), clock: o.Clock}
	if a.revokeURL == "" {
		a.revokeURL = appleRevokeURL
	}
	return a, nil
}

// appleBool reads email_verified and is_private_email, which Apple sends as a
// boolean or as the strings "true" and "false".
func appleBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true"
	}
	return false
}

// FormPost implements FormPoster: Apple returns the result by a form POST.
func (a *Apple) FormPost() bool { return true }

// Exchange implements Provider. The posted id_token, when there is one, must
// be valid and have the same sub as the one from the token endpoint. The name
// comes only from the unsigned user JSON; the email always comes from the ID
// token.
func (a *Apple) Exchange(ctx context.Context, cb Callback, _, nonce string) (Identity, error) {
	if cb.Error != "" {
		if cb.Error == "access_denied" || cb.Error == "user_cancelled_authorize" {
			return Identity{}, ErrCancelled
		}
		return Identity{}, errors.New("provider: apple: the provider returned an error")
	}
	id, tok, err := a.OIDC.exchange(ctx, cb, "", nonce)
	if err != nil {
		return Identity{}, err
	}
	if cb.IDToken != "" {
		posted, err := a.verifyIDToken(a.withClient(ctx), cb.IDToken, nonce)
		if err != nil {
			return Identity{}, err
		}
		if !secure.Equal(posted.Subject, id.Subject) {
			return Identity{}, fmt.Errorf("%w: the posted ID token is for another subject", ErrRefused)
		}
	}
	id.Name = appleName(cb.User)
	if a.store {
		id.RefreshToken = tok.RefreshToken
	}
	return id, nil
}

// appleName reads the name from Apple's user JSON; anything unreadable gives
// no name, because the JSON is unsigned and only a convenience.
func appleName(user string) string {
	if user == "" {
		return ""
	}
	var u struct {
		Name struct {
			First string `json:"firstName"`
			Last  string `json:"lastName"`
		} `json:"name"`
	}
	if json.Unmarshal([]byte(user), &u) != nil {
		return ""
	}
	return strings.TrimSpace(u.Name.First + " " + u.Name.Last)
}

// Revoke implements Revoker: it revokes a stored refresh token at Apple.
func (a *Apple) Revoke(ctx context.Context, refreshToken string) error {
	secret, err := a.secret.Secret()
	if err != nil {
		return err
	}
	form := url.Values{
		"client_id": {a.oauth.ClientID}, "client_secret": {secret},
		"token": {refreshToken}, "token_type_hint": {"refresh_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.revokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: the revoke endpoint could not be reached", ErrUnavailable)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: the revoke endpoint answered %d", ErrUnavailable, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("provider: apple: the revoke endpoint answered %d", resp.StatusCode)
	}
	return nil
}

// appleSubject is the event inside the events claim.
type appleSubject struct {
	Type string `json:"type"`
	Sub  string `json:"sub"`
}

// ParseEvent implements EventReceiver. Apple's notification carries one event.
func (a *Apple) ParseEvent(ctx context.Context, body []byte) ([]Event, error) {
	ev, err := a.parseEvent(ctx, body)
	if err != nil {
		return nil, err
	}
	return []Event{ev}, nil
}

// parseEvent reads Apple's notification. body is what Apple posted: a JSON object
// whose payload is a JWT. The JWT must be signed with Apple's keys, have the
// issuer https://appleid.apple.com and an aud that is the client id or one of
// the notification audiences. A payload with an exp must not have expired; one
// without is accepted when its iat is at most 24 hours old and at most 5
// minutes ahead (Apple's documented form). Its events claim is a JSON object or
// a string that holds that JSON, with the type and the sub.
//
// The event's ID is its jti, or the signed payload when it has none, and it is
// kept until the exp, or for a payload without one until 24 hours after the
// later of its iat and now (SEC-27). A payload whose keys cannot be fetched is
// ErrUnavailable; every other failure is ErrInvalidEvent. A type or a sub that
// is missing or unknown is not a failure.
func (a *Apple) parseEvent(ctx context.Context, body []byte) (Event, error) {
	invalid := func(why string) (Event, error) {
		return Event{}, fmt.Errorf("%w: %s", ErrInvalidEvent, why)
	}
	var post struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &post); err != nil || post.Payload == "" {
		return invalid("the body has no payload")
	}
	vctx, kf := withKeyFetch(a.withClient(ctx))
	idt, err := a.anyAudience.Verify(vctx, post.Payload)
	if err != nil {
		if kf.failed {
			return Event{}, fmt.Errorf("%w: the provider's keys could not be fetched", ErrUnavailable)
		}
		return invalid("the payload is not valid")
	}
	if !slices.ContainsFunc(idt.Audience, func(aud string) bool { return slices.Contains(a.audiences, aud) }) {
		return invalid("the payload is for another audience")
	}
	var claims struct {
		Events json.RawMessage `json:"events"`
		Exp    *json.Number    `json:"exp"`
		Iat    *json.Number    `json:"iat"`
		Jti    string          `json:"jti"`
	}
	if err := idt.Claims(&claims); err != nil {
		return invalid("the payload claims are not valid")
	}
	now := a.clock.Now()
	var expires time.Time
	switch {
	case claims.Exp != nil:
		exp, err := numericDate(claims.Exp)
		if err != nil {
			return invalid("the payload's exp is not a time")
		}
		// RFC 7519 4.1.4: the current time must be before exp. The id is kept
		// through exp (the hourly job deletes only what is past it), so a
		// payload accepted here is always recognised as a repeat.
		if !now.Before(exp) {
			return invalid("the payload has expired")
		}
		expires = exp
	case claims.Iat == nil:
		return invalid("the payload has neither an exp nor an iat")
	default:
		iat, err := numericDate(claims.Iat)
		if err != nil {
			return invalid("the payload's iat is not a time")
		}
		if now.Sub(iat) > 24*time.Hour || iat.Sub(now) > 5*time.Minute {
			return invalid("the payload was issued more than 24 hours ago or more than 5 minutes ahead")
		}
		from := now
		if iat.After(now) {
			from = iat
		}
		expires = from.Add(24 * time.Hour)
	}
	inner, err := eventSubject(claims.Events)
	if err != nil {
		return invalid("the events claim is not valid")
	}
	id := claims.Jti
	if id == "" {
		id = post.Payload
	}
	return Event{Set: EventSetApple, Type: inner.Type, Subject: inner.Sub, ID: id, Expires: expires}, nil
}

// numericDate reads a NumericDate (RFC 7519 2), which may carry a fraction of a
// second; its whole seconds are the time, as go-oidc reads them.
func numericDate(n *json.Number) (time.Time, error) {
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(f), 0).UTC(), nil
}

// eventSubject reads the events claim: a JSON object, or a string that holds
// that JSON. A claim that is missing or null holds no event and is an error.
func eventSubject(raw json.RawMessage) (appleSubject, error) {
	var inner appleSubject
	if len(raw) == 0 {
		return inner, errors.New("the events claim is missing")
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return inner, err
		}
		raw = []byte(s)
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return inner, errors.New("the events claim is null")
	}
	err := json.Unmarshal(raw, &inner)
	return inner, err
}
