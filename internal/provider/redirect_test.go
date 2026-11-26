package provider_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

// refusedElsewhere starts a server that fails the test when it is called: the
// target of a redirect the adapter must not follow.
func refusedElsewhere(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the adapter followed a redirect to %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts.URL + "/elsewhere"
}

// TestProviderRedirectsAndAudiences covers the row of the same name for a
// generic OIDC adapter: a 302 from discovery, token, user-info and key calls
// fails the call and the server it names is never called, and an ID token is
// accepted only when its azp, if present, is our client id and a token with
// two audiences has one (SEC-26).
//
// Covers: SEC-26
// Acceptance: Provider redirects and audiences
func TestProviderRedirectsAndAudiences(t *testing.T) {
	newAdapter := func(t *testing.T, userinfo bool) (*provider.OIDC, *mockidp.Server) {
		t.Helper()
		clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
		srv := mockidp.New(t, clk, mockidp.Generic)
		srv.SetUser(mockidp.User{Sub: "sub-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann Example"})
		o := provider.OIDCOptions{
			Issuer: srv.URL(), ClientID: srv.ClientID(), ClientSecret: srv.ClientSecret(),
			RedirectURI: "https://featherauth.example/cb", Timeout: time.Second, Clock: clk,
		}
		if userinfo {
			o.Endpoints.Userinfo = srv.URL() + "/userinfo"
		}
		a, err := provider.NewOIDC(context.Background(), o)
		if err != nil {
			t.Fatalf("NewOIDC: %v", err)
		}
		return a, srv
	}

	t.Run("discovery", func(t *testing.T) {
		clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
		srv := mockidp.New(t, clk, mockidp.Generic)
		srv.RedirectTo("discovery", refusedElsewhere(t))
		_, err := provider.NewOIDC(context.Background(), provider.OIDCOptions{
			Issuer: srv.URL(), ClientID: srv.ClientID(), ClientSecret: srv.ClientSecret(),
			RedirectURI: "https://featherauth.example/cb", Timeout: time.Second, Clock: clk,
		})
		if err == nil {
			t.Fatal("NewOIDC built an adapter from a discovery answer that redirected")
		}
	})

	t.Run("user-info", func(t *testing.T) {
		a, srv := newAdapter(t, true)
		code := loginCode(t, a)
		srv.RedirectTo("userinfo", refusedElsewhere(t))
		_, err := a.Exchange(context.Background(), provider.Callback{Code: code}, "", "n")
		if err == nil || errors.Is(err, provider.ErrUnavailable) {
			t.Fatalf("Exchange error = %v, want a server_error (a failure that is not unavailable)", err)
		}
	})

	t.Run("token", func(t *testing.T) {
		a, srv := newAdapter(t, false)
		code := loginCode(t, a)
		srv.RedirectTo("token", refusedElsewhere(t))
		_, err := a.Exchange(context.Background(), provider.Callback{Code: code}, "", "n")
		if err == nil || errors.Is(err, provider.ErrUnavailable) || errors.Is(err, provider.ErrRefused) {
			t.Fatalf("Exchange error = %v, want a server_error", err)
		}
	})

	t.Run("keys", func(t *testing.T) {
		a, srv := newAdapter(t, false)
		code := loginCode(t, a)
		srv.RedirectTo("jwks", refusedElsewhere(t))
		_, err := a.Exchange(context.Background(), provider.Callback{Code: code}, "", "n")
		if !errors.Is(err, provider.ErrUnavailable) {
			t.Fatalf("Exchange error = %v, want ErrUnavailable", err)
		}
	})

	audiences := []struct {
		name   string
		aud    func(cid string) any
		azp    func(cid string) (any, bool)
		accept bool
	}{
		{"two audiences without azp", func(cid string) any { return []any{cid, "another-client"} },
			func(string) (any, bool) { return nil, false }, false},
		{"two audiences with our azp", func(cid string) any { return []any{cid, "another-client"} },
			func(cid string) (any, bool) { return cid, true }, true},
		{"two audiences with another azp", func(cid string) any { return []any{cid, "another-client"} },
			func(string) (any, bool) { return "another-client", true }, false},
		{"one audience with another azp", func(cid string) any { return cid },
			func(string) (any, bool) { return "another-client", true }, false},
		{"two audiences with a number azp", func(cid string) any { return []any{cid, "another-client"} },
			func(string) (any, bool) { return 123, true }, false},
		{"two audiences with an array azp", func(cid string) any { return []any{cid, "another-client"} },
			func(cid string) (any, bool) { return []any{cid}, true }, false},
		{"two audiences with an empty azp", func(cid string) any { return []any{cid, "another-client"} },
			func(string) (any, bool) { return "", true }, false},
	}
	for _, c := range audiences {
		t.Run("ID token "+c.name, func(t *testing.T) {
			a, srv := newAdapter(t, false)
			code := loginCode(t, a)
			cid := srv.ClientID()
			srv.SetIDTokenClaims(func(m map[string]any) {
				m["aud"] = c.aud(cid)
				if v, set := c.azp(cid); set {
					m["azp"] = v
				} else {
					delete(m, "azp")
				}
			})
			id, err := a.Exchange(context.Background(), provider.Callback{Code: code}, "", "n")
			if c.accept {
				if err != nil || id.Subject != "sub-1" {
					t.Fatalf("Exchange = %+v, %v; want the identity", id, err)
				}
				return
			}
			if err == nil || id != (provider.Identity{}) {
				t.Fatalf("Exchange = %+v, %v; want a refused ID token", id, err)
			}
		})
	}
}
