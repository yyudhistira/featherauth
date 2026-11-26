package oidc_test

import (
	"context"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// appleLoginAs logs the Apple user "apple-1" in as the client.
func appleLoginAs(t *testing.T, e *server.Env, app server.App) {
	t.Helper()
	e.Mocks["apple"].SetUser(mockidp.User{Sub: "apple-1", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
	e.NewClient().Login(t, server.Authorize(app, "apple"))
}

// storedAppleToken returns the sealed token of the Apple identity, and the
// plain token it opens to ("" when nothing is stored).
func storedAppleToken(t *testing.T, e *server.Env) (sealed, plain string) {
	t.Helper()
	ctx := context.Background()
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		ident, err := tx.Identities().Find(ctx, rid, "apple", "apple-1")
		sealed = ident.ProviderRefreshTokenEnc
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if sealed != "" {
		p, err := e.Box.Open(sealed)
		if err != nil {
			t.Fatalf("the stored token does not open: %v", err)
		}
		plain = string(p)
	}
	return sealed, plain
}

// Covers: SEC-10 (part)
// Acceptance: Encryption key rotation (part)
func TestAppleLoginStoresTheSealedRefreshToken(t *testing.T) {
	app := server.ClientDelete
	e := server.New(t)
	apple := e.Mocks["apple"]

	appleLoginAs(t, e, app)
	sealed1, plain1 := storedAppleToken(t, e)
	if plain1 == "" || plain1 != apple.RefreshToken() || strings.Contains(sealed1, plain1) {
		t.Fatalf("stored %q opens to %q, want sealed %q", sealed1, plain1, apple.RefreshToken())
	}

	appleLoginAs(t, e, app) // a new token replaces the stored one
	if _, plain2 := storedAppleToken(t, e); plain2 != apple.RefreshToken() || plain2 == plain1 {
		t.Errorf("after the second login the token is %q, want %q", plain2, apple.RefreshToken())
	}
	kept := apple.RefreshToken()

	apple.OmitRefreshToken(true) // a login with none keeps the old one
	appleLoginAs(t, e, app)
	if _, plain3 := storedAppleToken(t, e); plain3 != kept {
		t.Errorf("after a login without a token it is %q, want %q", plain3, kept)
	}
}

// Covers: SEC-10 (part)
func TestAppleLoginWithoutStoreRefreshTokenStoresNothing(t *testing.T) {
	e := server.New(t)
	e.Reload(t, func(y string) string {
		return strings.Replace(y, "    team_id: TEAM123456\n", "    team_id: TEAM123456\n    store_refresh_token: false\n", 1)
	})
	appleLoginAs(t, e, server.ClientDelete)
	if sealed, _ := storedAppleToken(t, e); sealed != "" {
		t.Errorf("stored %q with store_refresh_token false", sealed)
	}
}
