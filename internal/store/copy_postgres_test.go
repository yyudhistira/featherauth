//go:build postgres

package store_test

import (
	"database/sql"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// queryText returns the one value of a query as text, "NULL" for a null.
func queryText(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	var v sql.NullString
	if err := db.QueryRowContext(t.Context(), query, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	if !v.Valid {
		return "NULL"
	}
	return v.String
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A seeded SQLite database with null and empty texts, both boolean values and ids
// that sort differently by bytes and by a locale is copied to an empty Postgres
// database: every table matches, and the values read back on Postgres are the
// values written on SQLite.
func TestCopyKeepsNullsEmptiesBooleansAndIDs(t *testing.T) {
	ctx := t.Context()
	src, path := testutil.NewStoreFile(t)
	testutil.SeedEveryTable(t, src)
	srv := testutil.NewPostgresServer(t)
	dst, secrets := srv.Target(t)

	tables, err := store.CopySQLiteToPostgres(ctx, testutil.DatabaseConfig(path), dst, secrets)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	db := srv.Connect(t, dst.Postgres.Database)
	counts := testutil.RowCounts(t, db)
	for _, tc := range tables {
		if !tc.Match || tc.Rows != counts[tc.Table] || tc.TargetRows != counts[tc.Table] {
			t.Errorf("table %s: match %v, source %d, target %d, on Postgres %d", tc.Table, tc.Match, tc.Rows, tc.TargetRows, counts[tc.Table])
		}
	}

	checks := []struct {
		name, query string
		args        []any
		want        string
	}{
		{"text", `SELECT email FROM users WHERE id = $1`, []any{"B-user"}, "b@example.com"},
		{"empty text of a user is null", `SELECT email FROM users WHERE id = $1`, []any{"a-user"}, "NULL"},
		{"empty name is null", `SELECT name FROM users WHERE id = $1`, []any{"B-user"}, "NULL"},
		{"true", `SELECT email_verified::text FROM users WHERE id = $1`, []any{"B-user"}, "true"},
		{"false", `SELECT email_verified::text FROM users WHERE id = $1`, []any{"a-user"}, "false"},
		{"set time", `SELECT (disabled_at IS NOT NULL)::text FROM users WHERE id = $1`, []any{"é-user"}, "true"},
		{"empty text not null", `SELECT email FROM identities WHERE id = $1`, []any{"B-identity"}, ""},
		{"null in a text", `SELECT provider_refresh_token_enc FROM identities WHERE id = $1`, []any{"B-identity"}, "NULL"},
		{"text in a text", `SELECT provider_refresh_token_enc FROM identities WHERE id = $1`, []any{"a-identity"}, "sealed"},
		{"empty text in a not-null column", `SELECT nonce FROM auth_codes WHERE code_hash = $1`, []any{string(secure.HashOf("code-2"))}, ""},
		{"unset used_at", `SELECT used_at::text FROM auth_codes WHERE code_hash = $1`, []any{string(secure.HashOf("code-2"))}, "NULL"},
		{"set used_at", `SELECT (used_at IS NOT NULL)::text FROM auth_codes WHERE code_hash = $1`, []any{string(secure.HashOf("code-1"))}, "true"},
		{"unset max_age", `SELECT max_age::text FROM auth_requests WHERE id = $1`, []any{"B-request"}, "NULL"},
		{"set max_age", `SELECT max_age::text FROM auth_requests WHERE id = $1`, []any{"a-request"}, "300"},
		{"unset nonce", `SELECT nonce FROM refresh_tokens WHERE id = $1`, []any{"B-token"}, "NULL"},
		{"set nonce", `SELECT nonce FROM refresh_tokens WHERE id = $1`, []any{"a-token"}, "n-1"},
		{"replaced_by", `SELECT replaced_by FROM refresh_tokens WHERE id = $1`, []any{"a-token"}, "B-token"},
		{"unset revoked_at", `SELECT (revoked_at IS NULL)::text FROM refresh_tokens WHERE id = $1`, []any{"B-token"}, "true"},
		{"unset user_id", `SELECT user_id FROM audit_events WHERE id = $1`, []any{"B-audit"}, "NULL"},
		{"empty details object", `SELECT details FROM audit_events WHERE id = $1`, []any{"B-audit"}, "{}"},
		{"details text", `SELECT (details LIKE '%revoke_at_provider%')::text FROM audit_events WHERE id = $1`, []any{"a-audit"}, "true"},
		{"ids as bytes", `SELECT string_agg(id, ',' ORDER BY id COLLATE "C") FROM users`, nil, "B-user,a-user,é-user"},
	}
	for _, c := range checks {
		if got := queryText(t, db, c.query, c.args...); got != c.want {
			t.Errorf("%s: %q = %q, want %q", c.name, c.query, got, c.want)
		}
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A target that holds rows is refused with ErrTargetNotEmpty, and its rows do not change.
func TestCopyRefusesANonEmptyTarget(t *testing.T) {
	ctx := t.Context()
	src, path := testutil.NewStoreFile(t)
	testutil.SeedEveryTable(t, src)
	srv := testutil.NewPostgresServer(t)
	dst, secrets := srv.Target(t)
	cfg := testutil.DatabaseConfig(path)
	if _, err := store.CopySQLiteToPostgres(ctx, cfg, dst, secrets); err != nil {
		t.Fatalf("first copy: %v", err)
	}
	db := srv.Connect(t, dst.Postgres.Database)
	before := testutil.RowCounts(t, db)

	_, err := store.CopySQLiteToPostgres(ctx, cfg, dst, secrets)
	if !errors.Is(err, store.ErrTargetNotEmpty) {
		t.Fatalf("second copy: %v, want ErrTargetNotEmpty", err)
	}
	if after := testutil.RowCounts(t, db); !maps.Equal(before, after) {
		t.Fatalf("the refused copy changed the target: %v, was %v", after, before)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A source at another schema version is refused with ErrSourceVersion before
// anything is written: the target gets no table at all.
func TestCopyRefusesAnotherSchemaVersion(t *testing.T) {
	src, path := testutil.NewStoreFile(t)
	testutil.SeedEveryTable(t, src)
	testutil.UnapplyNewestSQLiteMigration(t, path)
	srv := testutil.NewPostgresServer(t)
	dst, secrets := srv.Target(t)

	_, err := store.CopySQLiteToPostgres(t.Context(), testutil.DatabaseConfig(path), dst, secrets)
	if !errors.Is(err, store.ErrSourceVersion) {
		t.Fatalf("copy: %v, want ErrSourceVersion", err)
	}
	if counts := testutil.RowCounts(t, srv.Connect(t, dst.Postgres.Database)); len(counts) != 0 {
		t.Fatalf("the refused copy created tables on the target: %v", counts)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// The copy covers every table of the schema: the tables of the SQLite database,
// and the tables of the Data model of the design, are the tables the copy reports.
func TestCopyCoversEveryTableOfTheSchema(t *testing.T) {
	src, path := testutil.NewStoreFile(t)
	testutil.SeedEveryTable(t, src)
	srv := testutil.NewPostgresServer(t)
	dst, secrets := srv.Target(t)

	tables, err := store.CopySQLiteToPostgres(t.Context(), testutil.DatabaseConfig(path), dst, secrets)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	var copied []string
	for _, tc := range tables {
		copied = append(copied, tc.Table)
	}
	design := slices.Sorted(maps.Keys(parseDataModel(t)))
	if got := slices.Sorted(slices.Values(copied)); !slices.Equal(got, design) {
		t.Fatalf("copied tables = %v, the Data model has %v", got, design)
	}
	if schema := testutil.SQLiteTables(t, path); !slices.Equal(schema, design) {
		t.Fatalf("the SQLite schema has %v, the Data model has %v", schema, design)
	}
	pos := func(name string) int { return slices.Index(copied, name) }
	if !(pos("realms") < pos("users") && pos("users") < pos("identities")) {
		t.Fatalf("tables copied out of reference order: %v", copied)
	}
}

// Covers: FR-36 (part), FR-53 (part)
// Acceptance: Database copy (part)
// rate_limits has an integer key column: the copy of its rows to Postgres keeps
// every window, with the same count and checksum on both sides, and the seeded
// counts on Postgres are the source's.
func TestCopyCarriesRateLimitWindowsOntoPostgres(t *testing.T) {
	ctx := t.Context()
	src, path := testutil.NewStoreFile(t)
	testutil.SeedEveryTable(t, src)
	srv := testutil.NewPostgresServer(t)
	dst, secrets := srv.Target(t)

	tables, err := store.CopySQLiteToPostgres(ctx, testutil.DatabaseConfig(path), dst, secrets)
	if err != nil {
		t.Fatalf("copy with rate limit windows: %v", err)
	}
	db := srv.Connect(t, dst.Postgres.Database)
	counts := testutil.RowCounts(t, db)
	var found bool
	for _, tc := range tables {
		if tc.Table != "rate_limits" {
			continue
		}
		found = true
		if !tc.Match || tc.Rows != 2 || tc.TargetRows != 2 || counts["rate_limits"] != 2 {
			t.Errorf("rate_limits: match %v, source %d, target %d, on Postgres %d; want 2 rows on both sides",
				tc.Match, tc.Rows, tc.TargetRows, counts["rate_limits"])
		}
	}
	if !found {
		t.Fatal("the copy does not report rate_limits")
	}
}
