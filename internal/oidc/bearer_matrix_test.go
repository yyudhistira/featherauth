package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/testutil/testapi"
)

// Covers: SEC-20, SEC-14, SEC-16 (part)
// Acceptance: Token swap
// Acceptance: Realm isolation (part)
func TestBearerEndpointMatrix(t *testing.T) {
	app := server.ClientQuery
	endpoints := []struct {
		name string
		call func(t *testing.T, e *server.Env, access string) server.Response
	}{
		{"userinfo", func(t *testing.T, e *server.Env, a string) server.Response {
			return userinfo(t, e, http.MethodGet, a, nil)
		}},
		{"delete account", func(t *testing.T, e *server.Env, a string) server.Response {
			return deleteAccount(t, e, a)
		}},
		{"bearer logout", func(t *testing.T, e *server.Env, a string) server.Response {
			return logout(t, e, http.MethodPost, url.Values{}, http.Header{"Authorization": {"Bearer " + a}})
		}},
	}
	tokens := []struct {
		name    string
		expired bool
		pick    func(t *testing.T, e *server.Env, tk server.Tokens) string
	}{
		{"id token", false, func(t *testing.T, e *server.Env, tk server.Tokens) string { return tk.IDToken }},
		{"jwt refresh token", false, func(t *testing.T, e *server.Env, tk server.Tokens) string { return tk.RefreshToken }},
		{"another realm's access token", false, func(t *testing.T, e *server.Env, tk server.Tokens) string {
			a, _ := foreignTokens(t, e, "other", "s1")
			return a
		}},
		{"expired access token", true, func(t *testing.T, e *server.Env, tk server.Tokens) string {
			e.Clock.Advance(16 * time.Minute)
			return tk.AccessToken
		}},
	}
	for _, ep := range endpoints {
		for _, tc := range tokens {
			t.Run(ep.name+"/"+tc.name, func(t *testing.T) {
				e := logoutEnv(t, server.WithRefreshFormat("jwt"))
				tk := exchange(t, e, app)
				if decodeJWT(t, tk.RefreshToken).header["typ"] != "refresh+jwt" {
					t.Fatal("the refresh token is not a JWT")
				}
				raw := tc.pick(t, e, tk)
				wantBearerError(t, ep.call(t, e, raw), http.StatusUnauthorized, invalidTokenHeader, "invalid_token")
				// An API that verifies offline (UC-4) refuses the same token.
				srv := httptest.NewServer(e.Router)
				t.Cleanup(srv.Close)
				api := testapi.New(e.Clock, srv.URL+"/main/jwks.json", server.Issuer, app.ID)
				if _, err := api.Verify(context.Background(), raw); err == nil {
					t.Fatal("the test API accepted the token")
				}
				if tc.expired {
					return
				}
				if _, err := api.Verify(context.Background(), tk.AccessToken); err != nil {
					t.Fatalf("the test API refused the real access token: %v", err)
				}
				// The refusal changed nothing: the access token still works and the session is alive.
				if r := userinfo(t, e, http.MethodGet, tk.AccessToken, nil); r.Code != 200 {
					t.Fatalf("userinfo after the refusal: %d %q", r.Code, r.Body)
				}
				wantAlive(t, e, app, tk.RefreshToken)
			})
		}
	}
}

// Covers: SEC-14
func TestIssuedAccessTokensOutliveLogoutDeletionAndDisabling(t *testing.T) {
	app := server.ClientDelete
	cases := []struct {
		name string
		end  func(t *testing.T, e *server.Env, access, refresh string)
	}{
		{"logout", func(t *testing.T, e *server.Env, access, refresh string) {
			h := http.Header{"Authorization": {"Bearer " + access}}
			if r := logout(t, e, http.MethodPost, url.Values{}, h); r.Code != http.StatusNoContent {
				t.Fatalf("logout %d %q", r.Code, r.Body)
			}
			wantRevoked(t, e, app, refresh)
		}},
		{"deletion", func(t *testing.T, e *server.Env, access, refresh string) {
			if r := deleteAccount(t, e, access); r.Code != http.StatusNoContent {
				t.Fatalf("delete %d %q", r.Code, r.Body)
			}
		}},
		{"disabling", func(t *testing.T, e *server.Env, access, refresh string) {
			e.SetDisabled(t, true)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := server.New(t)
			tk := e.Exchange(t, app, e.Login(t, app))
			srv := httptest.NewServer(e.Router)
			t.Cleanup(srv.Close)
			api := testapi.New(e.Clock, srv.URL+"/main/jwks.json", server.Issuer, app.ID)
			tc.end(t, e, tk.AccessToken, tk.RefreshToken)
			// An API verifying offline still accepts the token ...
			if _, err := api.Verify(context.Background(), tk.AccessToken); err != nil {
				t.Fatalf("the test API refused the token after %s: %v", tc.name, err)
			}
			// ... while FeatherAuth's own endpoints look the user up (after logout the user is still there).
			if tc.name != "logout" {
				wantBearerError(t, userinfo(t, e, http.MethodGet, tk.AccessToken, nil), 401, invalidTokenHeader, "invalid_token")
			}
			// ... until it expires, 15 minutes after issue.
			e.Clock.Advance(14 * time.Minute)
			if _, err := api.Verify(context.Background(), tk.AccessToken); err != nil {
				t.Fatalf("the test API refused the token before it expired: %v", err)
			}
			e.Clock.Advance(2 * time.Minute)
			if _, err := api.Verify(context.Background(), tk.AccessToken); err == nil {
				t.Fatal("the test API accepted the token after it expired")
			}
		})
	}
}
