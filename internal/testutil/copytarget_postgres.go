//go:build postgres

package testutil

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver of database/sql

	"github.com/yyudhistira/featherauth/internal/config"
)

// Connect returns a pool to the database called database on the server, in its
// public schema. The pool is closed when the test ends.
func (s PostgresServer) Connect(t testing.TB, database string) *sql.DB {
	t.Helper()
	cfg, err := pgx.ParseConfig(s.dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", PostgresEnv, err)
	}
	cfg.Database = database
	db := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(t.Context()); err != nil {
		t.Fatalf("connect to %s: %v", database, err)
	}
	return db
}

// Target creates a database of its own on the server and returns the database
// and its secrets: the postgres block of database.yaml, with the password read
// from a password file in a directory of the test, as the service reads it.
func (s PostgresServer) Target(t testing.TB) (config.DatabaseFile, config.DatabaseSecrets) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "postgres_password"), []byte(s.Password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db := config.DatabaseFile{Driver: "postgres", Postgres: s.NewDatabase(t)}
	db.Postgres.PasswordFile = "postgres_password"
	secrets, ds := config.ReadDatabaseSecrets(dir, "database.yaml", &db, true)
	for _, d := range ds {
		if d.Severity == config.Error {
			t.Fatal(d.String())
		}
	}
	return db, secrets
}

// RowCounts returns the number of rows of every base table of the public schema
// of db, the migration table included. It is empty when the database has no table.
func RowCounts(t testing.TB, db *sql.DB) map[string]int64 {
	t.Helper()
	ctx := t.Context()
	rows, err := db.QueryContext(ctx, `SELECT table_name FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' ORDER BY table_name`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	_ = rows.Close()
	out := map[string]int64{}
	for _, name := range names {
		var n int64
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+pgx.Identifier{name}.Sanitize()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[name] = n
	}
	return out
}
