package provider_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

// Covers: SEC-13 (part)
func TestAdaptersLogNoSecrets(t *testing.T) {
	const clientSecret = "FAKE-CLIENT-SECRET-9f3a7c"
	clk := clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	srv := mockidp.New(t, clk, mockidp.Generic)
	u := srv.URL()
	oo := provider.OIDCOptions{
		Issuer: u, ClientID: "client-id", ClientSecret: clientSecret, RedirectURI: "https://x.example/cb",
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
	pemBody := strings.Join(strings.Split(strings.TrimSpace(string(pemKey)), "\n")[1:3], "")

	cases := map[string]struct {
		v    any
		want string
	}{
		"oidc": {generic, "oidc"}, "oidc value": {*generic, "oidc"},
		"google": {google, "google"}, "apple": {apple, "KEY1234567"}, "apple value": {*apple, "KEY1234567"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			log := logx.New(&buf, slog.LevelDebug, clk)
			log.Info("direct", "adapter", c.v)
			log.Info("nested", "details", map[string]any{"adapter": c.v})
			out := buf.String()
			for _, s := range []string{clientSecret, pemBody, "PRIVATE KEY"} {
				if strings.Contains(out, s) {
					t.Errorf("log holds %q: %s", s, out)
				}
			}
			if !strings.Contains(out, c.want) {
				t.Errorf("log does not name the adapter (%q): %s", c.want, out)
			}
		})
	}
}
