package provider_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/provider"
)

// The row "Provider user info" in one place: a generic oidc provider with the
// user-info endpoint unset and set, and the override of GitHub and Facebook.
//
// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info
func TestProviderUserInfoRow(t *testing.T) {
	t.Run("unset: no call", func(t *testing.T) {
		_, srv, err := userinfoLogin(t, "", dropProfile)
		if err != nil || userinfoCalls(srv) != 0 {
			t.Errorf("error %v, %d calls", err, userinfoCalls(srv))
		}
	})
	t.Run("a claim the ID token lacks is filled", func(t *testing.T) {
		id, srv, err := userinfoLogin(t, "mock", dropProfile)
		if err != nil || userinfoCalls(srv) != 1 || id.Email != "ann@example.com" || !id.EmailVerified || id.Name != "Ann Example" {
			t.Errorf("identity %+v, error %v, %d calls", id, err, userinfoCalls(srv))
		}
	})
	t.Run("an ID token claim is never replaced by a different one", func(t *testing.T) {
		id, _, err := userinfoLogin(t, "mock", func(c map[string]any) { c["email"] = "id@example.com"; c["name"] = "ID Name" })
		if err != nil || id.Email != "id@example.com" || id.Name != "ID Name" {
			t.Errorf("identity %+v, error %v", id, err)
		}
	})
	t.Run("a different sub is refused", func(t *testing.T) {
		_, _, err := userinfoLogin(t, "mock", func(c map[string]any) { c["sub"] = "someone-else" })
		if !errors.Is(err, provider.ErrRefused) {
			t.Errorf("error %v", err)
		}
	})
	for _, c := range []struct {
		name   string
		status int
		code   string
	}{{"a 5xx is temporarily_unavailable", 502, "temporarily_unavailable"}, {"a 4xx is a server_error", 401, "server_error"}} {
		t.Run(c.name, func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(c.status) }))
			defer api.Close()
			_, _, err := userinfoLogin(t, api.URL+"/userinfo", dropProfile)
			if err == nil {
				t.Fatal("Exchange succeeded")
			}
			if code, _ := provider.MapError(err); code != c.code {
				t.Errorf("error %v maps to %q, want %q", err, code, c.code)
			}
		})
	}
	t.Run("the override replaces GitHub's /user", func(t *testing.T) {
		env, srv := githubEnv(t, annGitHub)
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"id":4242,"name":"Custom User"}`))
		}))
		defer api.Close()
		p := newGitHub(t, env, func(o *provider.GitHubOptions) { o.UserURL = api.URL + "/custom/user" })
		id, err := githubExchange(t, p)
		if err != nil || id.Subject != "4242" || id.Name != "Custom User" {
			t.Fatalf("identity %+v, error %v", id, err)
		}
		for _, r := range srv.Requests() {
			if r.Path == "/user" {
				t.Error("the default /user was called")
			}
		}
	})
	t.Run("the override replaces Facebook's /me", func(t *testing.T) {
		env, srv := facebookEnv(t, annFacebook)
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/custom/me") {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write([]byte(`{"id":"777","email":"me@example.com"}`))
		}))
		defer api.Close()
		p := newFacebook(t, env, func(o *provider.FacebookOptions) { o.MeURL = api.URL + "/custom/me" })
		id, err := facebookExchange(t, p)
		if err != nil || id.Subject != "777" || id.Email != "me@example.com" {
			t.Fatalf("identity %+v, error %v", id, err)
		}
		for _, r := range srv.Requests() {
			if r.Path == "/me" {
				t.Error("the default /me was called")
			}
		}
	})
}
