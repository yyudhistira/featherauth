package user_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/testutil/testapi"
	"github.com/yyudhistira/featherauth/internal/token"
	"github.com/yyudhistira/featherauth/internal/user"
)

const wiringVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func claimsOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	msg, err := jws.Parse([]byte(raw), jws.WithCompact())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(msg.Payload(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// Covers: FR-08 (part)
// Acceptance: Token timing (part)
func TestPhase4WiringLoginToTokens(t *testing.T) {
	ctx := context.Background()

	// The real configuration, loaded from files.
	d := configdir.New(t)
	d.Server(t, "public_url: https://auth.example.com\n")
	d.Realm(t, "main", `name: main
keys:
  - { kid: rsa-new, file: secrets/rsa-new.pem, state: active }
providers:
  google:
    enabled: true
    client_id: 1234.apps.googleusercontent.com
    client_secret_file: secrets/google_secret
clients:
  web:
    redirect_uris: [https://app.example.com/callback]
    audience: https://api.example.com
`)
	d.RSAKey(t, "secrets/rsa-new.pem")
	d.Secret(t, "secrets/google_secret")
	fc := clock.NewFake(time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC))
	l, err := config.NewLoader(d.Root, fc, nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	snap := l.Current()
	realm, ok := snap.Realm("main")
	if !ok {
		t.Fatal("no realm main")
	}
	client := realm.Clients["web"]
	google := realm.Providers["google"]

	// The real services on a real store.
	st := testutil.NewStore(t)
	var logs bytes.Buffer
	log := logx.New(&logs, slog.LevelDebug, fc)
	aud := audit.NewWriter(st, log, fc, secure.Default)
	issuer := token.NewIssuer(fc, secure.Default, snap.Secrets())
	users := user.NewService(st, aud, log, fc, secure.Default)
	codes := token.NewCodes(st, issuer, fc, secure.Default)
	refresher := token.NewRefresher(st, issuer, fc, secure.Default)
	manager := user.NewManager(st, aud, nil, nil, log, fc, secure.Default, func(n config.RealmName) (*config.Realm, bool) {
		return &config.Realm{Name: n}, true // no clients: the sessions queue no logout
	})

	// The test API trusts the realm's published keys.
	keys, err := token.NewKeySet(realm, snap.Secrets())
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(keys.JWKS())
	}))
	t.Cleanup(jwks.Close)
	api := testapi.New(fc, jwks.URL, realm.Issuer(), "https://api.example.com")

	// 1. Resolve the provider identity.
	loginTime := fc.Now()
	u, err := users.Resolve(ctx, user.ResolveInput{
		Realm: realm, ProviderKey: "google", Provider: google,
		Identity: provider.Identity{Subject: "g-1", Email: "ann@gmail.com", EmailVerified: true, Name: "Ann"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// 2. Issue a code and exchange it with PKCE.
	sum := sha256.Sum256([]byte(wiringVerifier))
	code, err := codes.Issue(ctx, token.IssueInput{
		Realm: realm, Client: client, User: token.UserID(u.ID), RedirectURI: "https://app.example.com/callback",
		CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]), Nonce: "n-0S6", AuthTime: loginTime,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	grant, err := codes.Exchange(ctx, token.ExchangeInput{
		Realm: realm, Client: client, Code: code, RedirectURI: "https://app.example.com/callback", Verifier: wiringVerifier,
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	// 3. Refresh twice, checking every access token with the test API.
	type issued struct {
		grant *token.Grant
		at    time.Time
	}
	all := []issued{{grant, fc.Now()}}
	for range 2 {
		fc.Advance(time.Minute)
		g, err := refresher.Refresh(ctx, token.RefreshInput{Realm: realm, Client: client, Token: all[len(all)-1].grant.RefreshToken})
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		all = append(all, issued{g, fc.Now()})
	}
	first := claimsOf(t, all[0].grant.AccessToken)
	for i, it := range all {
		got, err := api.Verify(ctx, it.grant.AccessToken)
		if err != nil {
			t.Fatalf("token %d rejected by the API: %v", i, err)
		}
		if got.Sub != string(u.ID) {
			t.Errorf("token %d: sub = %q, want %q", i, got.Sub, u.ID)
		}
		// Token timing: iat is the issue time; auth_time, nonce and sid stay.
		for _, raw := range []string{it.grant.AccessToken, it.grant.IDToken} {
			c := claimsOf(t, raw)
			if int64(c["iat"].(float64)) != it.at.Unix() {
				t.Errorf("token %d: iat = %v, want %d", i, c["iat"], it.at.Unix())
			}
			if int64(c["auth_time"].(float64)) != loginTime.Unix() || c["nonce"] != "n-0S6" || c["sid"] != first["sid"] || c["sid"] == "" {
				t.Errorf("token %d: auth_time %v nonce %v sid %v", i, c["auth_time"], c["nonce"], c["sid"])
			}
		}
	}

	// 4. Delete the user: refresh fails, and the access token already issued
	// still verifies offline until it expires (SEC-14).
	if err := manager.Delete(ctx, "admin", "main", u.ID, user.DeleteOptions{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	last := all[len(all)-1].grant
	_, err = refresher.Refresh(ctx, token.RefreshInput{Realm: realm, Client: client, Token: last.RefreshToken})
	var ge *token.GrantError
	if !errors.As(err, &ge) || ge.Code != token.CodeInvalidGrant {
		t.Fatalf("refresh after deletion = %v, want invalid_grant", err)
	}
	if _, err := api.Verify(ctx, last.AccessToken); err != nil {
		t.Errorf("an issued access token must stay valid until it expires: %v", err)
	}
	fc.Advance(15 * time.Minute)
	if _, err := api.Verify(ctx, last.AccessToken); err == nil {
		t.Error("the access token is still accepted after it expired")
	}
}
