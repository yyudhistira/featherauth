package testutil

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// SeedEveryTable writes rows into every table of the Data model, through the
// repositories of one write transaction. The rows hold what a copy must keep:
// null and empty texts, both boolean values, a set and an unset time, ids that
// sort differently by bytes and by a locale ("B-user" sorts before "a-user" in
// bytes and after it in a locale), and a non-ASCII id. The realm "main" is
// created when it does not exist; the other realm is "other".
func SeedEveryTable(t testing.TB, s store.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	later := now.Add(time.Hour)
	err := s.Write(ctx, func(tx store.Tx) error {
		realm, err := tx.Realms().Ensure(ctx, "main", "B-realm-main", now)
		if err != nil {
			return err
		}
		if _, err := tx.Realms().Ensure(ctx, "other", "a-realm-other", now); err != nil {
			return err
		}

		users := []store.User{
			{ID: "B-user", RealmID: realm, Email: "b@example.com", EmailKey: "b@example.com", EmailVerified: true, CreatedAt: now, UpdatedAt: now},
			{ID: "a-user", RealmID: realm, CreatedAt: now, UpdatedAt: now},
			{ID: "é-user", RealmID: realm, Email: "e@example.com", EmailKey: "e@example.com", Name: "Zed", DisabledAt: now, CreatedAt: now, UpdatedAt: later},
		}
		for _, u := range users {
			if err := tx.Users().Create(ctx, u); err != nil {
				return err
			}
		}

		identities := []store.Identity{
			{ID: "B-identity", RealmID: realm, UserID: "B-user", Provider: "google", ProviderSub: "ß-1", CreatedAt: now},
			{ID: "a-identity", RealmID: realm, UserID: "é-user", Provider: "corp", ProviderSub: "a-sub", Email: "e@example.com", ProviderRefreshTokenEnc: "sealed", CreatedAt: now},
		}
		for _, i := range identities {
			if err := tx.Identities().Create(ctx, i); err != nil {
				return err
			}
		}

		maxAge := 300 * time.Second
		requests := []store.AuthRequest{
			{ID: "B-request", RealmID: realm, ClientID: "main-app", RedirectURI: "https://app.example.com/callback", ResponseMode: "query", ProviderNonce: "pn", Provider: "google", ProviderPKCEVerifier: "v", ExpiresAt: later},
			{ID: "a-request", RealmID: realm, ClientID: "main-app", RedirectURI: "https://app.example.com/callback", ClientState: "st", ResponseMode: "query", ProviderNonce: "pn", Provider: "corp", ProviderPKCEVerifier: "v", MaxAge: &maxAge, ExpiresAt: later},
		}
		for _, r := range requests {
			if err := tx.AuthRequests().Create(ctx, r); err != nil {
				return err
			}
		}

		codes := []store.AuthCode{
			{CodeHash: secure.HashOf("code-1"), RealmID: realm, UserID: "B-user", SessionID: "S-1", SessionStartedAt: now, ClientID: "main-app", RedirectURI: "https://app.example.com/callback", AuthTime: now, ExpiresAt: later, UsedAt: now, SSOIDHash: secure.HashOf("cookie-b")},
			{CodeHash: secure.HashOf("code-2"), RealmID: realm, UserID: "a-user", SessionID: "S-2", SessionStartedAt: now, ClientID: "main-app", RedirectURI: "https://app.example.com/callback", AuthTime: now, ExpiresAt: later},
		}
		for _, c := range codes {
			if err := tx.AuthCodes().Create(ctx, c); err != nil {
				return err
			}
		}

		if err := tx.Handoffs().Create(ctx, store.Handoff{IDHash: secure.HashOf("handoff-1"), AuthRequestID: "B-request", Payload: "{}", ExpiresAt: later}); err != nil {
			return err
		}

		tokens := []store.RefreshToken{
			{ID: "B-token", RealmID: realm, UserID: "B-user", ClientID: "main-app", TokenHash: secure.HashOf("rt-1"), SessionID: "S-1", SessionStartedAt: now, AuthTime: now, ExpiresAt: later, CreatedAt: now, SSOIDHash: secure.HashOf("cookie-b")},
			{ID: "a-token", RealmID: realm, UserID: "B-user", ClientID: "main-app", TokenHash: secure.HashOf("rt-2"), SessionID: "S-1", SessionStartedAt: now, AuthTime: now, Nonce: "n-1", ReplacedBy: "B-token", ExpiresAt: later, RevokedAt: now, CreatedAt: now, DPoPJKT: "jkt-1"},
		}
		for _, rt := range tokens {
			if err := tx.RefreshTokens().Insert(ctx, rt); err != nil {
				return err
			}
		}

		sessions := []store.SSOSession{
			{IDHash: secure.HashOf("cookie-b"), RealmID: realm, UserID: "B-user", IdentityID: "B-identity", Provider: "google",
				AuthTime: now, CreatedAt: now, LastUsedAt: now, ExpiresAt: later},
			{IDHash: secure.HashOf("cookie-a"), RealmID: realm, UserID: "é-user", IdentityID: "a-identity", Provider: "corp",
				AuthTime: now, CreatedAt: now, LastUsedAt: later, ExpiresAt: later.Add(time.Hour)},
		}
		for _, ss := range sessions {
			if err := tx.SSOSessions().Create(ctx, ss); err != nil {
				return err
			}
		}

		if err := tx.LogoutNotifications().Enqueue(ctx, store.LogoutNotification{
			ID: "a-logout", RealmID: realm, ClientID: "main-app", UserID: "B-user", SessionID: "S-1",
			Attempts: 1, NextAttemptAt: later, CreatedAt: now,
		}); err != nil {
			return err
		}
		if _, err := tx.ProviderEvents().Remember(ctx, realm, "google", secure.HashOf("event-1"), later); err != nil {
			return err
		}
		if _, err := tx.DPoPProofs().Use(ctx, secure.HashOf("proof-1"), later); err != nil {
			return err
		}
		// Two windows of one client key: a copy carries the rate limit counts (FR-53).
		for _, w := range []time.Time{now, now.Add(time.Minute)} {
			if _, err := tx.RateLimits().Hit(ctx, "203.0.113.7", w); err != nil {
				return err
			}
		}

		audit := []store.AuditEvent{
			{ID: "B-audit", RealmID: realm, Actor: "admin", Action: "user.update", CreatedAt: now},
			{ID: "a-audit", RealmID: realm, Actor: "system", Action: "user.delete", UserID: "B-user", Details: map[string]any{"revoke_at_provider": true}, CreatedAt: now},
		}
		for _, e := range audit {
			if err := tx.Audit().Insert(ctx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed every table: %v", err)
	}
}

// SQLiteTables returns the names of the tables of the SQLite database at path,
// sorted, without the migration table and SQLite's own tables.
func SQLiteTables(t testing.TB, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(context.Background(), `SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		if name == "goose_db_version" || strings.HasPrefix(name, "sqlite_") {
			continue
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// UnapplyNewestSQLiteMigration marks the newest applied migration of the SQLite
// database at path as not applied, so the database reads as one at the version
// before it. The version is read from the database, not written into the test.
func UnapplyNewestSQLiteMigration(t testing.TB, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(context.Background(),
		`UPDATE goose_db_version SET is_applied = 0 WHERE version_id = (SELECT MAX(version_id) FROM goose_db_version WHERE is_applied = 1)`); err != nil {
		t.Fatal(err)
	}
}
