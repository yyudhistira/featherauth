package providertest_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/provider/providertest"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

// reference is the smallest adapter that keeps the contract: a generic OIDC
// provider with PKCE. It proves the suite can pass.
type reference struct {
	base, clientID, secret, redirect string
	clk                              clock.Clock
	client                           *http.Client
	keys                             jwk.Set // cached after the first fetch
}

var _ provider.Provider = (*reference)(nil)

func newReference(env providertest.Env) *reference {
	return &reference{
		base: env.Server.URL(), clientID: env.Server.ClientID(), secret: env.Server.ClientSecret(),
		redirect: env.RedirectURI, clk: env.Clock,
		client: &http.Client{Timeout: env.Timeout, Transport: &http.Transport{}, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
}

func (*reference) Name() string { return "reference" }

func (r *reference) AuthURL(state, nonce, pkceChallenge string, opts provider.AuthOptions) string {
	q := url.Values{
		"client_id": {r.clientID}, "redirect_uri": {r.redirect}, "response_type": {"code"}, "scope": {"openid"},
		"state": {state}, "nonce": {nonce}, "code_challenge": {pkceChallenge}, "code_challenge_method": {"S256"},
	}
	if opts.Prompt != "" {
		q.Set("prompt", opts.Prompt)
	}
	if opts.MaxAge != nil {
		q.Set("max_age", strconv.Itoa(*opts.MaxAge))
	}
	if opts.LoginHint != "" {
		q.Set("login_hint", opts.LoginHint)
	}
	return r.base + "/authorize?" + q.Encode()
}

// get and post send a request with the adapter's own client; a transport
// failure or timeout is ErrUnavailable.
func (r *reference) do(ctx context.Context, method, u string, form url.Values) ([]byte, int, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, 0, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", provider.ErrUnavailable, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", provider.ErrUnavailable, err)
	}
	return b, resp.StatusCode, nil
}

// fetchKeys gets the provider's keys once, and once more when that fails.
func (r *reference) fetchKeys(ctx context.Context) (jwk.Set, error) {
	if r.keys != nil {
		return r.keys, nil
	}
	var lastErr error
	for range 2 {
		b, status, err := r.do(ctx, http.MethodGet, r.base+"/jwks", nil)
		if err == nil && status == http.StatusOK {
			set, perr := jwk.Parse(b)
			if perr != nil {
				return nil, perr
			}
			r.keys = set
			return set, nil
		}
		if err == nil {
			err = fmt.Errorf("%w: key endpoint answered %d", provider.ErrUnavailable, status)
		}
		lastErr = err
	}
	return nil, lastErr
}

func (r *reference) Exchange(ctx context.Context, cb provider.Callback, pkceVerifier, nonce string) (provider.Identity, error) {
	if cb.Error != "" {
		if cb.Error == "access_denied" {
			return provider.Identity{}, provider.ErrCancelled
		}
		return provider.Identity{}, errors.New("reference: the provider returned an error")
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {cb.Code}, "redirect_uri": {r.redirect},
		"client_id": {r.clientID}, "client_secret": {r.secret}, "code_verifier": {pkceVerifier},
	}
	// The code exchange is single use: one attempt, never retried.
	b, status, err := r.do(ctx, http.MethodPost, r.base+"/token", form)
	if err != nil {
		return provider.Identity{}, err
	}
	if status >= 500 {
		return provider.Identity{}, fmt.Errorf("%w: token endpoint answered %d", provider.ErrUnavailable, status)
	}
	if status != http.StatusOK {
		return provider.Identity{}, fmt.Errorf("reference: token endpoint answered %d", status)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(b, &tr); err != nil || tr.IDToken == "" {
		return provider.Identity{}, errors.New("reference: no ID token in the token response")
	}
	keys, err := r.fetchKeys(ctx)
	if err != nil {
		return provider.Identity{}, err
	}
	payload, err := jws.Verify([]byte(tr.IDToken), jws.WithKeySet(keys, jws.WithRequireKid(true)))
	if err != nil {
		return provider.Identity{}, fmt.Errorf("reference: ID token signature: %w", err)
	}
	var c struct {
		Iss           string  `json:"iss"`
		Sub           string  `json:"sub"`
		Aud           any     `json:"aud"`
		Azp           *string `json:"azp"`
		Exp           int64   `json:"exp"`
		Nonce         string  `json:"nonce"`
		Email         string  `json:"email"`
		EmailVerified bool    `json:"email_verified"`
		Name          string  `json:"name"`
		AuthTime      int64   `json:"auth_time"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return provider.Identity{}, fmt.Errorf("reference: ID token claims: %w", err)
	}
	var auds []string
	switch a := c.Aud.(type) {
	case string:
		auds = []string{a}
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok {
				auds = append(auds, s)
			}
		}
	}
	switch {
	case c.Iss != r.base:
		return provider.Identity{}, errors.New("reference: wrong iss")
	case !slices.Contains(auds, r.clientID):
		return provider.Identity{}, errors.New("reference: wrong aud")
	case c.Azp != nil && *c.Azp != r.clientID, c.Azp == nil && len(auds) > 1:
		return provider.Identity{}, errors.New("reference: wrong azp")
	case !r.clk.Now().Before(time.Unix(c.Exp, 0)):
		return provider.Identity{}, errors.New("reference: ID token expired")
	case c.Nonce == "" || nonce == "" || !secure.Equal(c.Nonce, nonce):
		return provider.Identity{}, errors.New("reference: wrong nonce")
	case c.Sub == "":
		return provider.Identity{}, errors.New("reference: no subject")
	}
	id := provider.Identity{Subject: c.Sub, Email: c.Email, EmailVerified: c.EmailVerified, Name: c.Name}
	if c.AuthTime != 0 {
		id.AuthTime = time.Unix(c.AuthTime, 0).UTC()
	}
	return id, nil
}

// Covers: FR-05 (part), FR-14 (part), SEC-03 (part)
// Acceptance: Provider adapters (part)
// Acceptance: Login hints (part)
func TestReferenceAdapterKeepsTheContract(t *testing.T) {
	zero := 0
	providertest.Run(t, providertest.Case{
		Profile: mockidp.Generic,
		OIDC:    true,
		PKCE:    true,
		New: func(t *testing.T, env providertest.Env) provider.Provider {
			return newReference(env)
		},
		Hints: []providertest.Hint{
			{Name: "none", Absent: []string{"prompt", "max_age", "login_hint"}},
			{Name: "login", Opts: provider.AuthOptions{Prompt: "login", MaxAge: &zero, LoginHint: "ann@example.com"},
				Want: url.Values{"prompt": {"login"}, "max_age": {"0"}, "login_hint": {"ann@example.com"}}},
			{Name: "consent", Opts: provider.AuthOptions{Prompt: "consent"},
				Want: url.Values{"prompt": {"consent"}}, Absent: []string{"max_age", "login_hint"}},
		},
	})
}
