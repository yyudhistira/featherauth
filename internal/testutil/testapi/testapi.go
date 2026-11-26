// Package testapi is the API of use case UC-4 for tests: it trusts tokens of
// one realm after fetching the realm's JWKS over HTTP. It is test support and
// only tests may import it.
package testapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
)

// JWKSCacheTTL is how long the API keeps a fetched JWKS, the max-age FeatherAuth
// publishes.
const JWKSCacheTTL = 300 * time.Second

// maxJWKS bounds the JWKS body the API reads.
const maxJWKS = 1 << 20

// Claims are the claims of an accepted access token.
type Claims struct {
	Sub string
	Exp time.Time
}

// API verifies access tokens offline, with only the JWKS. It keeps the JWKS
// for JWKSCacheTTL on the given clock and does not refetch earlier, not even
// for a kid it does not know: that is what makes a rotation without the
// waiting step fail.
type API struct {
	clock    clock.Clock
	client   *http.Client
	jwksURL  string
	issuer   string
	audience string

	mu        sync.Mutex
	set       jwk.Set
	fetchedAt time.Time
}

// New returns an API that fetches the JWKS from jwksURL and accepts access
// tokens with iss equal to issuer and aud equal to audience.
func New(c clock.Clock, jwksURL, issuer, audience string) *API {
	return &API{clock: c, client: &http.Client{Timeout: 5 * time.Second}, jwksURL: jwksURL, issuer: issuer, audience: audience}
}

// keys returns the cached key set, fetching it when there is none or it is
// 300 seconds old.
func (a *API) keys(ctx context.Context) (jwk.Set, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.clock.Now()
	if a.set != nil && now.Sub(a.fetchedAt) < JWKSCacheTTL {
		return a.set, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("testapi: %w", err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("testapi: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("testapi: fetch JWKS: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKS))
	if err != nil {
		return nil, fmt.Errorf("testapi: read JWKS: %w", err)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("testapi: parse JWKS: %w", err)
	}
	a.set, a.fetchedAt = set, now
	return set, nil
}

// Verify checks signature, typ, iss, aud and exp of an access token.
func (a *API) Verify(ctx context.Context, raw string) (Claims, error) {
	msg, err := jws.Parse([]byte(raw), jws.WithCompact())
	if err != nil || len(msg.Signatures()) != 1 {
		return Claims{}, errors.New("testapi: not a compact JWS")
	}
	h := msg.Signatures()[0].ProtectedHeaders()
	if typ, _ := h.Type(); typ != "at+jwt" {
		return Claims{}, fmt.Errorf("testapi: typ %q is not at+jwt", typ)
	}
	var m struct {
		Iss string   `json:"iss"`
		Sub string   `json:"sub"`
		Aud audience `json:"aud"`
		Exp *float64 `json:"exp"`
	}
	if err := json.Unmarshal(msg.Payload(), &m); err != nil {
		return Claims{}, errors.New("testapi: payload is not a JSON object")
	}
	set, err := a.keys(ctx)
	if err != nil {
		return Claims{}, err
	}
	kid, _ := h.KeyID()
	key, ok := set.LookupKeyID(kid)
	if !ok {
		return Claims{}, fmt.Errorf("testapi: kid %q is not in the cached JWKS", kid)
	}
	alg, ok := key.Algorithm()
	if !ok {
		return Claims{}, errors.New("testapi: the JWKS key has no alg")
	}
	if got, _ := h.Algorithm(); got.String() != alg.String() {
		return Claims{}, fmt.Errorf("testapi: alg %q does not match the key", got)
	}
	sigAlg, ok := h.Algorithm()
	if !ok {
		return Claims{}, errors.New("testapi: missing alg")
	}
	if _, err := jws.Verify([]byte(raw), jws.WithKey(sigAlg, key)); err != nil {
		return Claims{}, fmt.Errorf("testapi: bad signature: %w", err)
	}
	if m.Iss != a.issuer {
		return Claims{}, fmt.Errorf("testapi: iss %q is not %q", m.Iss, a.issuer)
	}
	if !m.Aud.has(a.audience) {
		return Claims{}, fmt.Errorf("testapi: aud does not include %q", a.audience)
	}
	if m.Exp == nil {
		return Claims{}, errors.New("testapi: no exp")
	}
	exp := time.Unix(int64(*m.Exp), 0).UTC()
	if !a.clock.Now().Before(exp) {
		return Claims{}, errors.New("testapi: token expired")
	}
	return Claims{Sub: m.Sub, Exp: exp}, nil
}

// audience is the aud claim: a string or an array of strings.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (a audience) has(want string) bool {
	for _, s := range a {
		if s == want {
			return true
		}
	}
	return false
}
