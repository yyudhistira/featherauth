package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/storetest"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

func TestSQLiteStoreContract(t *testing.T) {
	// Covers: FR-07 (part), FR-12 (part), FR-21 (part), SEC-06 (part), FR-45 (part), SEC-37 (part)
	// Acceptance: One verified email (part)
	// Acceptance: Multi-realm users (part)
	// Acceptance: Single sign-on start (part)
	storetest.Run(t, testutil.NewStore)
}

func TestUserAndIdentityLogValues(t *testing.T) {
	// Covers: SEC-13 (part)
	const email = "private.person@example.com"
	const sealed = "sealed-provider-token-value"
	const name = "Private Person"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	u := store.User{ID: "u1", RealmID: "r1", Email: email, EmailKey: email, EmailVerified: true, Name: name, CreatedAt: now, UpdatedAt: now}
	i := store.Identity{ID: "i1", RealmID: "r1", UserID: "u1", Provider: "google", ProviderSub: "sub1",
		Email: email, EmailVerified: true, ProviderRefreshTokenEnc: sealed, CreatedAt: now}

	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelInfo, clock.NewFake(now))
	log.Info("direct", "user", u, "identity", i)
	log.Info("nested", "details", map[string]any{"user": u, "identity": i, "list": []store.Identity{i}})
	log.Info("pointer", "user", &u, "identity", &i)

	out := buf.String()
	for _, secret := range []string{email, sealed, name} {
		if strings.Contains(out, secret) {
			t.Fatalf("log contains %q:\n%s", secret, out)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("invalid JSON line %q", line)
		}
	}
	if !strings.Contains(out, `"u1"`) || !strings.Contains(out, `"i1"`) {
		t.Fatalf("ids missing from the log:\n%s", out)
	}
}

func TestAuthRowsLogValues(t *testing.T) {
	// Covers: SEC-13 (part)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	maxAge := time.Minute
	ar := store.AuthRequest{ID: "state-value-1", RealmID: "r1", ClientID: "app", RedirectURI: "https://app.example/cb",
		ClientState: "client-state-value", Nonce: "nonce-value", ProviderNonce: "provider-nonce-value",
		CodeChallenge: "challenge-value", ResponseMode: "query", MaxAge: &maxAge, Provider: "google",
		ProviderPKCEVerifier: "pkce-verifier-value", ExpiresAt: now}
	ac := store.AuthCode{CodeHash: secure.HashOf("the-code-value"), RealmID: "r1", UserID: "u1", SessionID: "sess-1",
		ClientID: "app", RedirectURI: "https://app.example/cb", CodeChallenge: "challenge-value",
		Nonce: "nonce-value", SessionStartedAt: now, AuthTime: now, ExpiresAt: now}
	h := store.Handoff{IDHash: secure.HashOf("the-handoff-id"), AuthRequestID: "state-value-1",
		Payload: "payload-with-id-token-value", ExpiresAt: now}

	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelInfo, clock.NewFake(now))
	log.Info("direct", "request", ar, "code", ac, "handoff", h)
	log.Info("nested", "details", map[string]any{"request": ar, "code": ac, "handoff": h, "list": []store.AuthCode{ac}})
	log.Info("pointer", "request", &ar, "code", &ac, "handoff", &h)

	out := buf.String()
	for _, secret := range []string{"state-value-1", "client-state-value", "nonce-value", "challenge-value",
		"pkce-verifier-value", "the-code-value", string(ac.CodeHash), "the-handoff-id", string(h.IDHash),
		"payload-with-id-token-value", "https://app.example/cb"} {
		if strings.Contains(out, secret) {
			t.Fatalf("log contains %q:\n%s", secret, out)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("invalid JSON line %q", line)
		}
	}
	if !strings.Contains(out, `"sess-1"`) || !strings.Contains(out, `"u1"`) {
		t.Fatalf("ids missing from the log:\n%s", out)
	}
}

func TestRefreshTokenLogValue(t *testing.T) {
	// Covers: SEC-13 (part)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rt := store.RefreshToken{ID: "rt-1", RealmID: "r1", UserID: "u1", ClientID: "app",
		TokenHash: secure.HashOf("the-refresh-token"), SessionID: "sess-1", SessionStartedAt: now,
		AuthTime: now, Nonce: "nonce-value", ReplacedBy: "rt-2", ExpiresAt: now, CreatedAt: now}

	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelInfo, clock.NewFake(now))
	log.Info("direct", "token", rt)
	log.Info("nested", "details", map[string]any{"token": rt, "list": []store.RefreshToken{rt}})
	log.Info("pointer", "token", &rt)

	out := buf.String()
	for _, secret := range []string{"nonce-value", "the-refresh-token", string(rt.TokenHash)} {
		if strings.Contains(out, secret) {
			t.Fatalf("log contains %q:\n%s", secret, out)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("invalid JSON line %q", line)
		}
	}
	if !strings.Contains(out, `"rt-1"`) || !strings.Contains(out, `"sess-1"`) {
		t.Fatalf("ids missing from the log:\n%s", out)
	}
}

// Covers: FR-45 (part), SEC-37 (part), SEC-13 (part)
// Acceptance: Single sign-on start (part)
// A browser session logs its realm, user, identity, provider and expiry, never
// its id hash, directly or nested in a map.
func TestSSOSessionLogValueHidesTheHash(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ss := store.SSOSession{IDHash: secure.HashOf("cookie-value-secret"), RealmID: "r1", UserID: "u1",
		IdentityID: "i1", Provider: "google", AuthTime: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour)}

	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelInfo, clock.NewFake(now))
	log.Info("direct", "session", ss)
	log.Info("nested", "details", map[string]any{"session": ss, "list": []store.SSOSession{ss}})
	log.Info("pointer", "session", &ss)

	out := buf.String()
	for _, secret := range []string{string(ss.IDHash), "cookie-value-secret"} {
		if strings.Contains(out, secret) {
			t.Fatalf("log contains %q:\n%s", secret, out)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("invalid JSON line %q", line)
		}
	}
	if !strings.Contains(out, `"r1"`) || !strings.Contains(out, `"u1"`) {
		t.Fatalf("ids missing from the log:\n%s", out)
	}
}

func TestUsedErrorCarriesSession(t *testing.T) {
	err := fmt.Errorf("consume: %w", &store.UsedError{SessionID: "sess-9"})
	var ue *store.UsedError
	if !errors.Is(err, store.ErrUsed) || !errors.As(err, &ue) || ue.SessionID != "sess-9" {
		t.Fatalf("UsedError does not unwrap to ErrUsed with its session: %v", err)
	}
	if errors.Is(err, store.ErrExpired) {
		t.Fatal("UsedError matches ErrExpired")
	}
}

func TestRepositoriesReturnDatabaseErrors(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	called := 0
	var calls map[string]func() error
	_ = s.Write(ctx, func(tx store.Tx) error {
		if err := store.RawTx(tx).Rollback(); err != nil {
			t.Fatal(err)
		}
		u, i := store.User{ID: "u"}, store.Identity{ID: "i"}
		calls = map[string]func() error{
			"Ensure":                func() error { _, err := tx.Realms().Ensure(ctx, "r", "id", now); return err },
			"Realms.Find":           func() error { _, err := tx.Realms().Find(ctx, "r"); return err },
			"Users.Create":          func() error { return tx.Users().Create(ctx, u) },
			"Users.Get":             func() error { _, err := tx.Users().Get(ctx, "r", "u"); return err },
			"Users.Update":          func() error { return tx.Users().Update(ctx, u) },
			"Users.Delete":          func() error { return tx.Users().Delete(ctx, "r", "u") },
			"Users.FindVerified":    func() error { _, err := tx.Users().FindVerifiedByEmailKey(ctx, "r", "k"); return err },
			"Users.List":            func() error { _, err := tx.Users().ListByEmailKey(ctx, "r", "k"); return err },
			"Identities.Find":       func() error { _, err := tx.Identities().Find(ctx, "r", "p", "s"); return err },
			"Identities.Create":     func() error { return tx.Identities().Create(ctx, i) },
			"Identities.Update":     func() error { return tx.Identities().Update(ctx, i) },
			"Identities.List":       func() error { _, err := tx.Identities().ListByUser(ctx, "r", "u"); return err },
			"Identities.Delete":     func() error { return tx.Identities().Delete(ctx, "r", "i") },
			"Identities.SetToken":   func() error { return tx.Identities().SetProviderToken(ctx, "r", "i", "x") },
			"AuthRequests.Create":   func() error { return tx.AuthRequests().Create(ctx, store.AuthRequest{ID: "a"}) },
			"AuthRequests.Get":      func() error { _, err := tx.AuthRequests().Get(ctx, "a"); return err },
			"AuthRequests.Delete":   func() error { return tx.AuthRequests().Delete(ctx, "a") },
			"AuthCodes.Create":      func() error { return tx.AuthCodes().Create(ctx, store.AuthCode{}) },
			"AuthCodes.Consume":     func() error { _, err := tx.AuthCodes().Consume(ctx, "h", now); return err },
			"Handoffs.Create":       func() error { return tx.Handoffs().Create(ctx, store.Handoff{}) },
			"Handoffs.Take":         func() error { _, err := tx.Handoffs().Take(ctx, "h", now); return err },
			"Refresh.Insert":        func() error { return tx.RefreshTokens().Insert(ctx, store.RefreshToken{}) },
			"Refresh.Find":          func() error { _, err := tx.RefreshTokens().FindByHash(ctx, "r", "h"); return err },
			"Refresh.FindByID":      func() error { _, err := tx.RefreshTokens().FindByID(ctx, "r", "a"); return err },
			"Refresh.Extend":        func() error { return tx.RefreshTokens().Extend(ctx, "r", "a", now) },
			"Refresh.MarkReplaced":  func() error { return tx.RefreshTokens().MarkReplaced(ctx, "a", "b") },
			"Refresh.RevokeSession": func() error { _, err := tx.RefreshTokens().RevokeSession(ctx, "r", "s", now); return err },
			"Refresh.RevokeOthers":  func() error { return tx.RefreshTokens().RevokeOthers(ctx, "r", "s", "k", now) },
			"Refresh.DeleteUser":    func() error { _, err := tx.RefreshTokens().DeleteUser(ctx, "r", "u"); return err },
			"Refresh.RevokeUser":    func() error { _, err := tx.RefreshTokens().RevokeUser(ctx, "r", "u", now); return err },
			"AuthRequests.Expired":  func() error { _, err := tx.AuthRequests().DeleteExpired(ctx, now); return err },
			"AuthCodes.Expired":     func() error { _, err := tx.AuthCodes().DeleteExpired(ctx, now); return err },
			"Handoffs.Expired":      func() error { _, err := tx.Handoffs().DeleteExpired(ctx, now); return err },
			"ProviderEvents.Remember": func() error {
				_, err := tx.ProviderEvents().Remember(ctx, "r", "p", "h", now)
				return err
			},
			"ProviderEvents.Expired": func() error { _, err := tx.ProviderEvents().DeleteExpired(ctx, now); return err },
			"Audit.Insert":           func() error { return tx.Audit().Insert(ctx, store.AuditEvent{ID: "a"}) },
			"Audit.List":             func() error { _, err := tx.Audit().List(ctx, "r", now); return err },
			"Refresh.DeleteExpired":  func() error { _, err := tx.RefreshTokens().DeleteExpired(ctx, now); return err },
		}
		for name, fn := range calls {
			called++
			err := fn()
			if err == nil {
				t.Errorf("%s on a finished transaction returned no error", name)
			}
			if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict) {
				t.Errorf("%s: database error mapped to %v", name, err)
			}
		}
		return nil
	})
	if called != len(calls) || called == 0 {
		t.Fatalf("ran %d of %d calls", called, len(calls))
	}
}
