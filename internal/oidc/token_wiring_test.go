package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/testutil/testapi"
)

// jwt is a decoded, unverified token.
type jwt struct {
	header, claims map[string]any
}

func decodeJWT(t *testing.T, raw string) jwt {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("%q is not a JWT", raw)
	}
	var out jwt
	for i, dst := range []*map[string]any{&out.header, &out.claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func (j jwt) str(k string) string { s, _ := j.claims[k].(string); return s }

func (j jwt) unix(k string) time.Time {
	f, _ := j.claims[k].(float64)
	return time.Unix(int64(f), 0).UTC()
}

// Covers: SEC-05 (part), SEC-06 (part)
// Acceptance: Token types
// Acceptance: Token timing
func TestTokensPerClientType(t *testing.T) {
	clients := []struct {
		app          server.App
		confidential bool
		noChallenge  bool
	}{
		{server.ClientQuery, false, false},
		{server.ClientConfidential, true, false},
		{server.ClientLegacy, false, true},
	}
	for _, alg := range []string{"RS256", "ES256"} {
		for _, format := range []string{"opaque", "jwt"} {
			t.Run(alg+" "+format, func(t *testing.T) {
				e := server.New(t, server.WithAlgorithm(alg), server.WithRefreshFormat(format))
				srv := httptest.NewServer(e.Router)
				t.Cleanup(srv.Close)
				for _, c := range clients {
					t.Run(c.app.ID, func(t *testing.T) {
						api := testapi.New(e.Clock, srv.URL+"/main/jwks.json", server.Issuer, c.app.ID)
						verify := func(raw string) error { _, err := api.Verify(context.Background(), raw); return err }
						withSecret := func(f url.Values) url.Values {
							if c.confidential {
								f.Set("client_secret", e.Secret(c.app.ID))
							}
							return f
						}

						var kv []string
						form := []string{}
						if c.noChallenge {
							kv = []string{"code_challenge", "-", "code_challenge_method", "-"}
							form = []string{"code_verifier", "-"}
						}
						loginAt := e.Clock.Now()
						res := e.Login(t, c.app, kv...)
						first := wantTokens(t, post(t, e, withSecret(server.CodeForm(c.app, res, form...)), nil))

						check := func(tk server.Tokens, issuedAt time.Time) (access, id jwt) {
							t.Helper()
							access, id = decodeJWT(t, tk.AccessToken), decodeJWT(t, tk.IDToken)
							// the access token: RFC 9068, signed with tokens.algorithm
							if access.header["typ"] != "at+jwt" || access.header["alg"] != alg {
								t.Errorf("access header %v", access.header)
							}
							if access.str("client_id") != c.app.ID || access.str("azp") != c.app.ID || access.str("iss") != server.Issuer {
								t.Errorf("access claims %v", access.claims)
							}
							if !access.unix("iat").Equal(issuedAt) || !access.unix("exp").Equal(issuedAt.Add(15*time.Minute)) {
								t.Errorf("access iat %v exp %v, issued %v", access.unix("iat"), access.unix("exp"), issuedAt)
							}
							if err := verify(tk.AccessToken); err != nil {
								t.Errorf("the test API refused the access token: %v", err)
							}
							// the ID token: always RS256, never an access token
							if id.header["typ"] != "JWT" || id.header["alg"] != "RS256" {
								t.Errorf("ID token header %v", id.header)
							}
							if id.str("aud") != c.app.ID || !id.unix("iat").Equal(issuedAt) || !id.unix("exp").Equal(issuedAt.Add(15*time.Minute)) || id.str("at_hash") == "" {
								t.Errorf("ID token claims %v", id.claims)
							}
							if err := verify(tk.IDToken); err == nil {
								t.Error("the test API accepted an ID token")
							}
							// the refresh token
							if format == "jwt" {
								rt := decodeJWT(t, tk.RefreshToken)
								if rt.header["typ"] != "refresh+jwt" || rt.header["alg"] != alg || rt.str("aud") != server.Issuer ||
									rt.str("azp") != c.app.ID || rt.str("sid") != access.str("sid") {
									t.Errorf("refresh token %v %v", rt.header, rt.claims)
								}
								if err := verify(tk.RefreshToken); err == nil {
									t.Error("the test API accepted a refresh token")
								}
							} else if strings.Contains(tk.RefreshToken, ".") {
								t.Errorf("the opaque refresh token %q looks like a JWT", tk.RefreshToken)
							}
							return access, id
						}

						a0, i0 := check(first, loginAt)
						if a0.str("nonce") != "n-1" || i0.str("nonce") != "n-1" || a0.str("sid") == "" {
							t.Errorf("claims at login: %v %v", a0.claims, i0.claims)
						}
						if !a0.unix("auth_time").Equal(loginAt) || !i0.unix("auth_time").Equal(loginAt) {
							t.Errorf("auth_time %v, login at %v", a0.unix("auth_time"), loginAt)
						}

						// two refreshes, each later than the last
						tk := first
						for i := range 2 {
							e.Clock.Advance(5 * time.Minute)
							rf := withSecret(server.RefreshForm(c.app, tk.RefreshToken))
							tk = wantTokens(t, post(t, e, rf, nil))
							a, id := check(tk, e.Clock.Now())
							for _, j := range []jwt{a, id} {
								if !j.unix("auth_time").Equal(loginAt) || j.str("nonce") != "n-1" || j.str("sid") != a0.str("sid") {
									t.Errorf("refresh %d: auth_time %v nonce %q sid %q", i+1, j.unix("auth_time"), j.str("nonce"), j.str("sid"))
								}
							}
							if a.str("jti") == a0.str("jti") {
								t.Errorf("refresh %d: the access token id did not change", i+1)
							}
						}
					})
				}
			})
		}
	}
}
