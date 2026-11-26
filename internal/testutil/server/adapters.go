// Package server builds the service for tests: the real parts wired together
// over a temporary store and the mock identity provider. It is test support
// and only tests may import it.
package server

import (
	"context"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

// Registry gives the adapters it holds for their provider keys and the inner
// registry's for every other. The registry built from configuration cannot
// reach a mock for GitHub (the emails URL is fixed) or Apple (the ID token
// algorithm is fixed), so tests build those two adapters directly, with the
// real adapter code, and name them here.
type Registry struct {
	provider.Registry
	Adapters map[config.ProviderKey]provider.Provider
}

var _ provider.Registry = Registry{}

// Get implements provider.Registry.
func (r Registry) Get(realm config.RealmName, key config.ProviderKey) (provider.Provider, bool) {
	if a, ok := r.Adapters[key]; ok {
		return a, true
	}
	return r.Registry.Get(realm, key)
}

// AdapterTimeout is the timeout of the adapters built here.
const AdapterTimeout = 5 * time.Second

// GitHub builds the GitHub adapter against a mock with the GitHub profile.
func GitHub(t testing.TB, srv *mockidp.Server, redirectURI string, mods ...func(*provider.GitHubOptions)) *provider.GitHub {
	t.Helper()
	u := srv.URL()
	opts := provider.GitHubOptions{
		ClientID: srv.ClientID(), ClientSecret: srv.ClientSecret(), RedirectURI: redirectURI,
		Scopes: []string{"read:user", "user:email"}, PKCE: true, AllowSignup: true, RequireVerifiedEmail: true,
		AuthorizeURL: u + "/login/oauth/authorize", TokenURL: u + "/login/oauth/access_token",
		UserURL: u + "/user", EmailsURL: u + "/user/emails", Timeout: AdapterTimeout,
	}
	for _, m := range mods {
		m(&opts)
	}
	p, err := provider.NewGitHub(opts)
	if err != nil {
		t.Fatalf("NewGitHub: %v", err)
	}
	return p
}

// Apple builds the Apple adapter against a mock with the Apple profile. The
// mock accepts any client secret.
func Apple(t testing.TB, clk clock.Clock, srv *mockidp.Server, redirectURI string) *provider.Apple {
	t.Helper()
	_, pemKey := testutil.ECKey(t)
	srv.SetSecretCheck(func(string) error { return nil })
	u := srv.URL()
	p, err := provider.NewApple(context.Background(), provider.AppleOptions{
		OIDCOptions: provider.OIDCOptions{
			ClientID: srv.ClientID(), RedirectURI: redirectURI, Scopes: []string{"name", "email"},
			Endpoints:  provider.OIDCEndpoints{Authorize: u + "/authorize", Token: u + "/token", JWKS: u + "/jwks"},
			Algorithms: []string{"ES256"}, // the mock signs with ES256
			Timeout:    AdapterTimeout, Clock: clk,
		},
		TeamID: "TEAM123456", KeyID: "KEY1234567", PrivateKeyPEM: pemKey, Lifetime: 5 * time.Minute,
		StoreRefreshToken: true, RevokeURL: u + "/revoke",
		NotificationAudiences: []string{"com.example.app"},
	})
	if err != nil {
		t.Fatalf("NewApple: %v", err)
	}
	return p
}

// Google builds the Google adapter against a mock with the Google profile;
// the real adapter's issuer and RISC configuration are fixed, so the mock's own
// are used.
func Google(t testing.TB, clk clock.Clock, srv *mockidp.Server, redirectURI string, mods ...func(*provider.GoogleOptions)) *provider.Google {
	t.Helper()
	opts := provider.GoogleOptions{OIDCOptions: provider.OIDCOptions{
		Issuer: srv.URL(), ClientID: srv.ClientID(), ClientSecret: srv.ClientSecret(), RedirectURI: redirectURI,
		Scopes: []string{"openid", "email", "profile"}, Timeout: AdapterTimeout, Clock: clk,
	}, RISCConfigurationURL: srv.URL() + mockidp.RISCConfigPath}
	for _, m := range mods {
		m(&opts)
	}
	p, err := provider.NewGoogle(context.Background(), opts)
	if err != nil {
		t.Fatalf("NewGoogle: %v", err)
	}
	return p
}

// Facebook builds the Facebook adapter against a mock with the Facebook
// profile.
func Facebook(t testing.TB, clk clock.Clock, srv *mockidp.Server, redirectURI string, mods ...func(*provider.FacebookOptions)) *provider.Facebook {
	t.Helper()
	u := srv.URL()
	opts := provider.FacebookOptions{
		ClientID: srv.ClientID(), ClientSecret: srv.ClientSecret(), RedirectURI: redirectURI,
		GraphVersion: "v26.0", Scopes: []string{"public_profile", "email"}, Fields: []string{"id", "name", "email"},
		AuthorizeURL: u + "/dialog/oauth", TokenURL: u + "/oauth/access_token", GraphURL: u, Timeout: AdapterTimeout, Clock: clk,
	}
	for _, m := range mods {
		m(&opts)
	}
	p, err := provider.NewFacebook(opts)
	if err != nil {
		t.Fatalf("NewFacebook: %v", err)
	}
	return p
}
