package store

import (
	"context"
	"database/sql"
	"io/fs"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pressly/goose/v3"
)

// Covers: SEC-23 (part)
func TestHandoffIndexMigrationKeepsTheNewestRowPerLogin(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sub, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, db, sub)
	if err != nil {
		t.Fatal(err)
	}
	// A version 1 database may hold two handoffs of one login: the older one
	// is removed when the index is added, and the other login's row stays.
	if _, err := p.UpTo(ctx, 1); err != nil {
		t.Fatal(err)
	}
	for _, row := range [][2]string{{"old", "a"}, {"other", "b"}, {"new", "a"}} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO callback_handoffs (id_hash, auth_request_id, payload, expires_at) VALUES (?, ?, 'p', 1)`,
			row[0], row[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := db.QueryContext(ctx, `SELECT id_hash FROM callback_handoffs ORDER BY id_hash`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		got = append(got, id)
	}
	_ = rows.Close()
	if want := []string{"new", "other"}; !slices.Equal(got, want) {
		t.Fatalf("handoffs after the migration = %v, want %v", got, want)
	}
	var unique int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_index_list('callback_handoffs') WHERE name = 'callback_handoffs_auth_request_id' AND "unique" = 1`,
	).Scan(&unique); err != nil || unique != 1 {
		t.Fatalf("unique index on auth_request_id: %d, %v", unique, err)
	}
}

// Covers: SEC-27 (part)
// The migration that adds provider_event_ids goes up and down, and up again.
func TestProviderEventIDsMigrationUpAndDown(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sub, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, db, sub)
	if err != nil {
		t.Fatal(err)
	}
	exists := func() int {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'provider_event_ids'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := p.UpTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if n := exists(); n != 0 {
		t.Fatalf("provider_event_ids exists before its migration")
	}
	if _, err := p.UpTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if n := exists(); n != 1 {
		t.Fatalf("provider_event_ids after up: %d tables", n)
	}
	var pk string
	if err := db.QueryRowContext(ctx,
		`SELECT group_concat(name) FROM (SELECT name FROM pragma_table_info('provider_event_ids') WHERE pk > 0 ORDER BY pk)`).Scan(&pk); err != nil {
		t.Fatal(err)
	}
	if pk != "realm_id,provider,id_hash" {
		t.Fatalf("primary key = %q", pk)
	}
	if _, err := p.Down(ctx); err != nil {
		t.Fatal(err)
	}
	if n := exists(); n != 0 {
		t.Fatalf("provider_event_ids after down: %d tables", n)
	}
	if _, err := p.UpTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if n := exists(); n != 1 {
		t.Fatalf("provider_event_ids after the second up: %d tables", n)
	}
}

// Covers: FR-44 (part)
// The migration that adds refresh_tokens.dpop_jkt goes up and down, and up again.
func TestRefreshDPoPJKTMigrationUpAndDown(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sub, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, db, sub)
	if err != nil {
		t.Fatal(err)
	}
	column := func() int {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pragma_table_info('refresh_tokens') WHERE name = 'dpop_jkt'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := p.UpTo(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if n := column(); n != 0 {
		t.Fatalf("dpop_jkt exists before its migration")
	}
	if _, err := p.UpTo(ctx, 6); err != nil {
		t.Fatal(err)
	}
	if n := column(); n != 1 {
		t.Fatalf("dpop_jkt after up: %d columns", n)
	}
	if _, err := p.Down(ctx); err != nil {
		t.Fatal(err)
	}
	if n := column(); n != 0 {
		t.Fatalf("dpop_jkt after down: %d columns", n)
	}
	if _, err := p.UpTo(ctx, 6); err != nil {
		t.Fatal(err)
	}
	if n := column(); n != 1 {
		t.Fatalf("dpop_jkt after the second up: %d columns", n)
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
// The migration that adds sso_sessions, its index and the sso_id_hash columns goes
// up and down, and up again.
func TestSSOSessionsMigrationUpAndDown(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sub, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, db, sub)
	if err != nil {
		t.Fatal(err)
	}
	count := func(query string) int {
		var n int
		if err := db.QueryRowContext(ctx, query).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// table, index, auth_codes.sso_id_hash and refresh_tokens.sso_id_hash
	state := func() [4]int {
		return [4]int{
			count(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'sso_sessions'`),
			count(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'sso_sessions_user_id'`),
			count(`SELECT COUNT(*) FROM pragma_table_info('auth_codes') WHERE name = 'sso_id_hash'`),
			count(`SELECT COUNT(*) FROM pragma_table_info('refresh_tokens') WHERE name = 'sso_id_hash'`),
		}
	}
	if _, err := p.UpTo(ctx, 6); err != nil {
		t.Fatal(err)
	}
	if got := state(); got != [4]int{} {
		t.Fatalf("sso objects before their migration: %v", got)
	}
	if _, err := p.UpTo(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if got := state(); got != [4]int{1, 1, 1, 1} {
		t.Fatalf("sso objects after up: %v", got)
	}
	if _, err := p.Down(ctx); err != nil {
		t.Fatal(err)
	}
	if got := state(); got != [4]int{} {
		t.Fatalf("sso objects after down: %v", got)
	}
	if _, err := p.UpTo(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if got := state(); got != [4]int{1, 1, 1, 1} {
		t.Fatalf("sso objects after the second up: %v", got)
	}
}
