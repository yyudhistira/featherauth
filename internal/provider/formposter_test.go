package provider_test

import (
	"context"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

// Covers: SEC-23 (part)
func TestFormPostIsImplementedByAppleOnly(t *testing.T) {
	clk := clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	srv := mockidp.New(t, clk, mockidp.Generic)
	u := srv.URL()
	oo := provider.OIDCOptions{
		Issuer: u, ClientID: "client-id", ClientSecret: "secret", RedirectURI: "https://x.example/cb",
		Endpoints: provider.OIDCEndpoints{Authorize: u + "/authorize", Token: u + "/token", JWKS: u + "/jwks"},
		Timeout:   time.Second, Clock: clk,
	}
	generic, err := provider.NewOIDC(context.Background(), oo)
	if err != nil {
		t.Fatal(err)
	}
	google, err := provider.NewGoogle(context.Background(), provider.GoogleOptions{OIDCOptions: oo})
	if err != nil {
		t.Fatal(err)
	}
	_, pemKey := testutil.ECKey(t)
	apple, err := provider.NewApple(context.Background(), provider.AppleOptions{
		OIDCOptions: oo, TeamID: "TEAM123456", KeyID: "KEY1234567", PrivateKeyPEM: pemKey, Lifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	github, err := provider.NewGitHub(provider.GitHubOptions{
		ClientID: "client-id", ClientSecret: "secret", RedirectURI: "https://x.example/cb",
		Scopes: []string{"read:user"}, AuthorizeURL: u + "/a", TokenURL: u + "/t", UserURL: u + "/u",
		EmailsURL: u + "/e", Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	facebook, err := provider.NewFacebook(provider.FacebookOptions{
		ClientID: "client-id", ClientSecret: "secret", RedirectURI: "https://x.example/cb", GraphVersion: "v26.0",
		Scopes: []string{"email"}, AuthorizeURL: u + "/a", TokenURL: u + "/t", GraphURL: u, Timeout: time.Second,
		Clock: clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		adapter any
		posts   bool
	}{
		{"apple", apple, true},
		{"google", google, false},
		{"github", github, false},
		{"facebook", facebook, false},
		{"generic oidc", generic, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fp, ok := c.adapter.(provider.FormPoster)
			if ok != c.posts {
				t.Fatalf("implements FormPoster = %v, want %v", ok, c.posts)
			}
			if ok && fp.FormPost() != c.posts {
				t.Fatalf("FormPost() = %v, want %v", fp.FormPost(), c.posts)
			}
		})
	}
}
