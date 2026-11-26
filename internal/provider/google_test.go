package provider_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/provider/providertest"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

func newGoogle(t *testing.T, env providertest.Env, hd string) *provider.Google {
	t.Helper()
	p, err := provider.NewGoogle(context.Background(), provider.GoogleOptions{
		OIDCOptions: provider.OIDCOptions{
			Issuer: env.Server.URL(), ClientID: env.Server.ClientID(), ClientSecret: env.Server.ClientSecret(),
			RedirectURI: env.RedirectURI, Scopes: []string{"openid", "email", "profile"},
			Timeout: env.Timeout, Clock: env.Clock,
		},
		HostedDomain: hd,
	})
	if err != nil {
		t.Fatalf("NewGoogle: %v", err)
	}
	return p
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider adapters (part)
// Acceptance: Login hints (part)
func TestGoogleKeepsTheProviderContract(t *testing.T) {
	zero := 0
	providertest.Run(t, providertest.Case{
		Profile: mockidp.Google, OIDC: true, PKCE: true,
		New: func(t *testing.T, env providertest.Env) provider.Provider { return newGoogle(t, env, "") },
		Hints: []providertest.Hint{
			{Name: "none", Absent: []string{"prompt", "max_age", "login_hint", "hd"}},
			{Name: "prompt=login", Opts: provider.AuthOptions{Prompt: "login"},
				Want: url.Values{"prompt": {"select_account"}}, Absent: []string{"max_age"}},
			{Name: "max_age", Opts: provider.AuthOptions{MaxAge: &zero},
				Want: url.Values{"prompt": {"select_account"}}, Absent: []string{"max_age"}},
			{Name: "prompt=select_account", Opts: provider.AuthOptions{Prompt: "select_account"},
				Want: url.Values{"prompt": {"select_account"}}},
			{Name: "prompt=consent", Opts: provider.AuthOptions{Prompt: "consent"},
				Want: url.Values{"prompt": {"consent"}}, Absent: []string{"max_age"}},
			{Name: "consent with max_age", Opts: provider.AuthOptions{Prompt: "consent", MaxAge: &zero},
				Want: url.Values{"prompt": {"select_account consent"}}, Absent: []string{"max_age"}},
			{Name: "consent with login_hint", Opts: provider.AuthOptions{Prompt: "consent", LoginHint: "a@b.c"},
				Want: url.Values{"prompt": {"consent"}, "login_hint": {"a@b.c"}}},
			{Name: "login_hint", Opts: provider.AuthOptions{LoginHint: "ann@example.com"},
				Want: url.Values{"login_hint": {"ann@example.com"}}, Absent: []string{"prompt"}},
		},
	})
}

// Covers: SEC-03 (part)
// Acceptance: Provider adapters (part)
func TestGoogleHostedDomain(t *testing.T) {
	// the hd parameter is sent, and a user of that domain signs in
	providertest.Run(t, providertest.Case{
		Profile: mockidp.Google, OIDC: true, PKCE: true,
		New:  func(t *testing.T, env providertest.Env) provider.Provider { return newGoogle(t, env, "example.com") },
		User: mockidp.User{Sub: "sub-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann Example", HD: "example.com"},
		Hints: []providertest.Hint{
			{Name: "hd sent", Want: url.Values{"hd": {"example.com"}}},
		},
	})

	// the domain is compared case-insensitively
	providertest.Run(t, providertest.Case{
		Profile: mockidp.Google, OIDC: true, PKCE: true,
		New:  func(t *testing.T, env providertest.Env) provider.Provider { return newGoogle(t, env, "Example.COM") },
		User: mockidp.User{Sub: "sub-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann Example", HD: "example.com"},
	})

	for _, c := range []struct{ name, hd string }{{"a different hd claim", "other.example"}, {"no hd claim", ""}} {
		t.Run(c.name+" is refused", func(t *testing.T) {
			clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
			srv := mockidp.New(t, clk, mockidp.Google)
			srv.SetUser(mockidp.User{Sub: "sub-1", Email: "ann@example.com", EmailVerified: true, HD: c.hd})
			p := newGoogle(t, providertest.Env{Server: srv, Clock: clk, RedirectURI: "https://featherauth.example/cb", Timeout: time.Second}, "example.com")
			code := loginCode(t, p)
			_, err := p.Exchange(context.Background(), provider.Callback{Code: code}, "", "n")
			if !errors.Is(err, provider.ErrRefused) {
				t.Errorf("error = %v, want ErrRefused", err)
			}
		})
	}
}

// Covers: FR-14 (part)
func TestGoogleIssuerConstant(t *testing.T) {
	if provider.GoogleIssuer != "https://accounts.google.com" {
		t.Errorf("GoogleIssuer = %q", provider.GoogleIssuer)
	}
}

// Covers: FR-14 (part), SEC-03 (part)
// Acceptance: Provider user info (part)
func TestGoogleCallsUserinfoWhenSet(t *testing.T) {
	clk := clock.NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	srv := mockidp.New(t, clk, mockidp.Google)
	srv.SetUser(mockidp.User{Sub: "sub-1", Email: "ann@example.com", EmailVerified: true, Name: "Ann Example"})
	env := providertest.Env{Server: srv, Clock: clk, RedirectURI: "https://featherauth.example/cb", Timeout: time.Second}
	g, err := provider.NewGoogle(context.Background(), provider.GoogleOptions{OIDCOptions: provider.OIDCOptions{
		Issuer: srv.URL(), ClientID: srv.ClientID(), ClientSecret: srv.ClientSecret(), RedirectURI: env.RedirectURI,
		Endpoints: provider.OIDCEndpoints{Userinfo: srv.URL() + "/userinfo"}, Timeout: env.Timeout, Clock: clk,
	}})
	if err != nil {
		t.Fatal(err)
	}
	code := loginCode(t, g)
	srv.SetIDTokenClaims(func(c map[string]any) {
		c["nonce"] = "n"
		delete(c, "name")
	})
	id, err := g.Exchange(context.Background(), provider.Callback{Code: code}, "", "n")
	if err != nil || id.Name != "Ann Example" {
		t.Errorf("identity %+v, error %v", id, err)
	}
}
