package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

const specProviders = `  google:
    enabled: true
    client_id: g-id
    client_secret_file: secrets/main/google_secret
    hosted_domain: example.com
    timeout: 7s
    scopes: [openid, email]
    endpoints: {authorize: "http://127.0.0.1:9/a", token: "http://127.0.0.1:9/t", jwks: "http://127.0.0.1:9/j", userinfo: "http://127.0.0.1:9/gi"}
  corp:
    type: oidc
    enabled: true
    client_id: c-id
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9"
    timeout: 3s
    endpoints: {authorize: "http://127.0.0.1:9/a", token: "http://127.0.0.1:9/t", jwks: "http://127.0.0.1:9/j", userinfo: "http://127.0.0.1:9/u"}
  apple:
    enabled: true
    client_id: com.example.web
    team_id: TEAM123456
    key_id: KEY1234567
    private_key_file: secrets/main/apple.p8
    store_refresh_token: false
    client_secret_lifetime: 10m
    scopes: [email]
    endpoints: {userinfo: "http://127.0.0.1:9/ai"}
  github:
    enabled: true
    client_id: gh-id
    client_secret_file: secrets/main/github_secret
    allow_signup: false
    endpoints: {authorize: "http://127.0.0.1:9/ga", token: "http://127.0.0.1:9/gt", userinfo: "http://127.0.0.1:9/gu"}
  facebook:
    enabled: true
    client_id: fb-id
    client_secret_file: secrets/main/facebook_secret
    require_email: true
    fields: [name, email]
    endpoints: {authorize: "http://127.0.0.1:9/fa", token: "http://127.0.0.1:9/ft", userinfo: "http://127.0.0.1:9/fm"}
`

func specFixture(t *testing.T) (*config.Realm, config.Secrets, clock.Clock) {
	t.Helper()
	l, _ := testutil.NewProviderConfig(t, specProviders, "google", "corp", "github", "facebook")
	snap := l.Current()
	r, ok := snap.Realm("main")
	if !ok {
		t.Fatal("no realm main")
	}
	return r, snap.Secrets(), clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
}

func specFor(t *testing.T, key string, mod func(*config.Provider)) (spec, error) {
	t.Helper()
	r, secrets, clk := specFixture(t)
	p := *r.Providers[config.ProviderKey(key)]
	if mod != nil {
		mod(&p)
	}
	return newSpec(clk, r, config.ProviderKey(key), &p, secrets)
}

// Covers: FR-14 (part)
// Acceptance: Provider config (part)
func TestSpecFromConfigForEveryProviderType(t *testing.T) {
	r, secrets, clk := specFixture(t)
	redirect := func(key string) string { return r.EndpointURL(config.EndpointCallback, config.ProviderKey(key)) }
	get := func(key string) spec {
		t.Helper()
		sp, err := newSpec(clk, r, config.ProviderKey(key), r.Providers[config.ProviderKey(key)], secrets)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		return sp
	}
	secretOf := func(key string) string { return secrets.ClientSecret("main", config.ProviderSecret, key) }

	t.Run("google", func(t *testing.T) {
		sp := get("google")
		o := sp.google
		if sp.kind != "google" || o.Issuer != GoogleIssuer || o.HostedDomain != "example.com" ||
			o.ClientID != "g-id" || o.ClientSecret != secretOf("google") || o.ClientSecret == "" ||
			o.RedirectURI != redirect("google") || o.Timeout != 7*time.Second || o.Clock != clk ||
			strings.Join(o.Scopes, " ") != "openid email" ||
			o.Endpoints != (OIDCEndpoints{Authorize: "http://127.0.0.1:9/a", Token: "http://127.0.0.1:9/t", JWKS: "http://127.0.0.1:9/j", Userinfo: "http://127.0.0.1:9/gi"}) {
			t.Errorf("google spec = %+v", o)
		}
	})
	t.Run("oidc", func(t *testing.T) {
		sp := get("corp")
		o := sp.oidc
		if sp.kind != "oidc" || o.Issuer != "http://127.0.0.1:9" || o.ClientID != "c-id" || o.ClientSecret != secretOf("corp") ||
			o.ClientSecret == "" || o.RedirectURI != redirect("corp") || o.Timeout != 3*time.Second ||
			strings.Join(o.Scopes, " ") != "openid email profile" ||
			o.Endpoints != (OIDCEndpoints{Authorize: "http://127.0.0.1:9/a", Token: "http://127.0.0.1:9/t", JWKS: "http://127.0.0.1:9/j", Userinfo: "http://127.0.0.1:9/u"}) {
			t.Errorf("oidc spec = %+v", o)
		}
	})
	t.Run("apple", func(t *testing.T) {
		sp := get("apple")
		o := sp.apple
		if sp.kind != "apple" || o.ClientID != "com.example.web" || o.TeamID != "TEAM123456" || o.KeyID != "KEY1234567" ||
			o.Lifetime != 10*time.Minute || o.StoreRefreshToken || o.RevokeURL != "" || o.RedirectURI != redirect("apple") ||
			o.Timeout != 10*time.Second {
			t.Errorf("apple spec = %+v", o)
		}
		// Apple has no user-info endpoint: the option is not passed on
		if o.Endpoints.Userinfo != "" {
			t.Errorf("apple userinfo = %q", o.Endpoints.Userinfo)
		}
		// the scopes are the configured ones (FR-56): the fixture lists email
		if strings.Join(o.Scopes, " ") != "email" {
			t.Errorf("apple scopes = %v, want email", o.Scopes)
		}
		block, _ := pem.Decode(o.PrivateKeyPEM)
		if block == nil {
			t.Fatal("the Apple key is not PEM")
		}
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			t.Errorf("the Apple key does not parse: %v", err)
		}
	})
	t.Run("github", func(t *testing.T) {
		sp := get("github")
		o := sp.github
		if sp.kind != "github" || o.ClientID != "gh-id" || o.ClientSecret != secretOf("github") || o.ClientSecret == "" ||
			o.AllowSignup || !o.PKCE || !o.RequireVerifiedEmail || o.RedirectURI != redirect("github") ||
			o.AuthorizeURL != "http://127.0.0.1:9/ga" || o.TokenURL != "http://127.0.0.1:9/gt" ||
			o.UserURL != "http://127.0.0.1:9/gu" || o.EmailsURL != "" || o.Timeout != 10*time.Second ||
			strings.Join(o.Scopes, " ") != "read:user user:email" {
			t.Errorf("github spec = %+v", o)
		}
	})
	t.Run("facebook", func(t *testing.T) {
		sp := get("facebook")
		o := sp.facebook
		if sp.kind != "facebook" || o.ClientID != "fb-id" || o.ClientSecret != secretOf("facebook") || o.ClientSecret == "" ||
			o.GraphVersion != "v26.0" || !o.RequireEmail || strings.Join(o.Fields, ",") != "name,email" ||
			strings.Join(o.Scopes, ",") != "public_profile,email" || o.RedirectURI != redirect("facebook") ||
			o.AuthorizeURL != "http://127.0.0.1:9/fa" || o.TokenURL != "http://127.0.0.1:9/ft" || o.GraphURL != "" || o.MeURL != "http://127.0.0.1:9/fm" {
			t.Errorf("facebook spec = %+v", o)
		}
	})
}

// Covers: FR-14 (part)
// Acceptance: Provider config (part)
func TestSpecGitHubDefaultsAreNotGoZeroValues(t *testing.T) {
	sp, err := specFor(t, "github", func(p *config.Provider) { p.AllowSignup = true })
	if err != nil {
		t.Fatal(err)
	}
	if !sp.github.AllowSignup || !sp.github.PKCE || !sp.github.RequireVerifiedEmail {
		t.Errorf("github spec = %+v", sp.github)
	}
}

// Covers: FR-14 (part)
func TestOpenIDScopes(t *testing.T) {
	for _, c := range []struct{ in, want []string }{
		{nil, []string{"openid", "email", "profile"}},
		{[]string{"email"}, []string{"openid", "email"}},
		{[]string{"profile", "openid"}, []string{"profile", "openid"}},
	} {
		if got := openIDScopes(c.in); !slices.Equal(got, c.want) {
			t.Errorf("openIDScopes(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// Covers: FR-14 (part)
func TestSpecErrors(t *testing.T) {
	cases := map[string]struct {
		key string
		mod func(*config.Provider)
	}{
		"facebook flow oidc":   {"facebook", func(p *config.Provider) { p.Flow = "oidc" }},
		"unknown type":         {"corp", func(p *config.Provider) { p.Type = "saml" }},
		"no timeout":           {"github", func(p *config.Provider) { p.Timeout = 0 }},
		"no github secret":     {"github", func(p *config.Provider) { p.ClientSecretFile = ""; p.ClientID = "" }},
		"apple without a name": {"apple", func(p *config.Provider) { p.TeamID = "" }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			sp, err := specFor(t, c.key, c.mod)
			if err == nil {
				// a spec that builds lazily fails at build time instead
				if _, err = sp.build(context.Background()); err == nil {
					t.Error("neither newSpec nor build failed")
				}
			}
		})
	}

	t.Run("missing client secret", func(t *testing.T) {
		r, _, clk := specFixture(t)
		p := *r.Providers["github"]
		if _, err := newSpec(clk, r, "github", &p, nil); err == nil {
			t.Error("newSpec accepted a provider with no secrets loaded")
		}
	})
}

// The Apple spec carries the configured scopes, in the configured order, and an
// empty list stays empty so that the authorize URL has no scope parameter.
//
// Covers: FR-56 (part)
func TestSpecAppleScopesAreTheConfiguredOnes(t *testing.T) {
	for _, c := range []struct {
		name   string
		scopes []string
		want   string
	}{
		{"default pair", []string{"name", "email"}, "name email"},
		{"reversed", []string{"email", "name"}, "email name"},
		{"name alone", []string{"name"}, "name"},
		{"empty", []string{}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp, err := specFor(t, "apple", func(p *config.Provider) { p.Scopes = c.scopes })
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(sp.apple.Scopes, " "); got != c.want {
				t.Errorf("scopes = %q, want %q", got, c.want)
			}
		})
	}
}
