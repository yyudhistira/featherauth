package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// queuedLogouts counts the logout notifications of the database: a claim far in
// the future returns every row.
func queuedLogouts(t *testing.T, e *adminEnv) int {
	t.Helper()
	var rows []store.LogoutNotification
	err := e.svc.Write(context.Background(), func(tx store.Tx) (err error) {
		rows, err = tx.LogoutNotifications().Claim(context.Background(), e.clock.Now().Add(365*24*time.Hour), 1000)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// revoked reports whether the refresh token with that secret is revoked.
func revoked(t *testing.T, e *adminEnv, token string) bool {
	t.Helper()
	var rt store.RefreshToken
	err := e.svc.Read(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(context.Background(), "main")
		if err != nil {
			return err
		}
		rt, err = tx.RefreshTokens().FindByHash(context.Background(), rid, secure.HashOf(token))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return !rt.RevokedAt.IsZero()
}

// Covers: FR-43 (part)
// Acceptance: Revoking commands without a configuration
// Without a usable configuration the revoking commands keep their plain behaviour:
// they revoke, disable or succeed as before, queue no logout notification and
// log one warning.
func TestRevokingCommandsWithoutAConfiguration(t *testing.T) {
	const warning = "back-channel logout not queued: the realm's configuration is not available"
	forEachDB(t, func(t *testing.T, d dbDriver) {
		t.Run("session revoke ends one session", func(t *testing.T) {
			e := newAdminEnvWith(t, d, false)
			e.addSessionToken(t, "t1", "tok1", "sess-1", "u1", nil)
			e.addSessionToken(t, "t2", "tok2", "sess-2", "u1", nil)
			r := e.run(t, "session", "revoke", "main", "u1", "--session", "sess-1")
			if r.code != 0 {
				t.Fatalf("%+v", r)
			}
			if !revoked(t, e, "tok1") || revoked(t, e, "tok2") {
				t.Fatal("the session revoked is not the one named")
			}
			if !strings.Contains(r.stderr, warning) || !strings.Contains(r.stderr, `"level":"WARN"`) {
				t.Fatalf("stderr %q, want the warning", r.stderr)
			}
			if n := queuedLogouts(t, e); n != 0 {
				t.Fatalf("%d logout notifications queued, want none", n)
			}
		})
		t.Run("user disable ends every session and disables the user", func(t *testing.T) {
			e := newAdminEnvWith(t, d, false)
			e.addSessionToken(t, "t1", "tok1", "sess-1", "u1", nil)
			e.addSessionToken(t, "t2", "tok2", "sess-2", "u1", nil)
			r := e.run(t, "user", "disable", "main", "u1")
			if r.code != 0 {
				t.Fatalf("%+v", r)
			}
			if e.user(t, "u1").DisabledAt.IsZero() {
				t.Fatal("the user is not disabled")
			}
			if !revoked(t, e, "tok1") || !revoked(t, e, "tok2") {
				t.Fatal("the sessions of the disabled user are alive")
			}
			if !strings.Contains(r.stderr, warning) {
				t.Fatalf("stderr %q, want the warning", r.stderr)
			}
			if n := queuedLogouts(t, e); n != 0 {
				t.Fatalf("%d logout notifications queued, want none", n)
			}
		})
		t.Run("a user with no session is still disabled", func(t *testing.T) {
			e := newAdminEnvWith(t, d, false)
			r := e.run(t, "user", "disable", "main", "u2")
			if r.code != 0 {
				t.Fatalf("%+v", r)
			}
			if e.user(t, "u2").DisabledAt.IsZero() {
				t.Fatal("the user is not disabled")
			}
			if !strings.Contains(r.stderr, warning) || !strings.Contains(r.stderr, `"level":"WARN"`) {
				t.Fatalf("stderr %q, want the warning", r.stderr)
			}
			if n := queuedLogouts(t, e); n != 0 {
				t.Fatalf("%d logout notifications queued, want none", n)
			}
		})
	})
}
