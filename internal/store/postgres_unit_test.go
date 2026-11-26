package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestRebindNumbersThePlaceholders(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{name: "no placeholder", in: "SELECT 1", want: "SELECT 1"},
		{name: "one", in: "SELECT id FROM realms WHERE name = ?", want: "SELECT id FROM realms WHERE name = $1"},
		{name: "several in order", in: "a = ? AND b = ? AND c = ?", want: "a = $1 AND b = $2 AND c = $3"},
		{name: "question mark in a literal stays", in: "x = '?' AND y = ?", want: "x = '?' AND y = $1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rebind(tc.in); got != tc.want {
				t.Fatalf("rebind(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestPostgresUniqueViolationIsConflict(t *testing.T) {
	foreignKey := &pgconn.PgError{Code: "23503"}
	tests := []struct {
		name     string
		err      error
		conflict bool
	}{
		{name: "unique violation", err: &pgconn.PgError{Code: "23505"}, conflict: true},
		{name: "wrapped unique violation", err: fmt.Errorf("insert: %w", &pgconn.PgError{Code: "23505"}), conflict: true},
		{name: "foreign key violation is not a conflict", err: foreignKey},
		{name: "other error is returned as it is", err: errors.New("boom")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapWriteErr(tc.err)
			if errors.Is(got, ErrConflict) != tc.conflict {
				t.Fatalf("mapWriteErr(%v) = %v, conflict %v, want %v", tc.err, got, errors.Is(got, ErrConflict), tc.conflict)
			}
			if !tc.conflict && got != tc.err {
				t.Fatalf("mapWriteErr changed the error: %v", got)
			}
		})
	}
}

// The text of a unique violation names the key and never its values: an email
// is one of them, and the text reaches the logs through errors.
func TestUniqueViolationTextHoldsNoKeyValues(t *testing.T) {
	err := mapWriteErr(&pgconn.PgError{Code: "23505", ConstraintName: "users_verified_email_key",
		Detail: "Key (realm_id, email_key)=(r1, ann@example.org) already exists."})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("mapWriteErr = %v, want ErrConflict", err)
	}
	if strings.Contains(err.Error(), "ann@example.org") || !strings.Contains(err.Error(), "users_verified_email_key") {
		t.Fatalf("text = %q, want the key name and no value", err.Error())
	}
}

// Postgres has no built-in snapshot: the backup of a Postgres store names pg_dump
// and touches no database, so the store needs none here.
func TestPostgresBackupNamesPgDump(t *testing.T) {
	s := &postgresStore{}
	err := s.Backup(context.Background(), filepath.Join(t.TempDir(), "b.db"))
	if err == nil || !strings.Contains(err.Error(), "pg_dump") {
		t.Fatalf("Backup error = %v, want one that names pg_dump", err)
	}
}

// refusingConnector is a database that cannot be reached; it is not a store.
type refusingConnector struct{ err error }

func (c refusingConnector) Connect(context.Context) (driver.Conn, error) { return nil, c.err }

func (c refusingConnector) Driver() driver.Driver { return nil }

func TestNewPostgresFailsWhenTheDatabaseIsUnreachable(t *testing.T) {
	db := sql.OpenDB(refusingConnector{err: errors.New("connection refused")})
	s, err := NewPostgres(context.Background(), db)
	if err == nil || !strings.Contains(err.Error(), "migrate database") {
		t.Fatalf("NewPostgres = %v, %v; want a migration error", s, err)
	}
	if s != nil {
		t.Fatal("NewPostgres returned a store with its error")
	}
	// A failed NewPostgres closes the database it was given.
	if err := db.PingContext(context.Background()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("ping after the failed NewPostgres = %v, want the database closed", err)
	}
}

// The Postgres migrations are the shared ones, each replaced by its file of the
// same name under migrations/postgres: a Postgres file exists only where the SQL
// differs, so it never adds a version of its own.
func TestPostgresMigrationsReplaceSharedFiles(t *testing.T) {
	fsys, err := postgresMigrations()
	if err != nil {
		t.Fatal(err)
	}
	shared, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	names := func(f fs.FS) []string {
		entries, err := fs.ReadDir(f, ".")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range entries {
			if !e.IsDir() {
				out = append(out, e.Name())
			}
		}
		slices.Sort(out)
		return out
	}
	sharedNames := names(shared)
	if got := names(fsys); !slices.Equal(got, sharedNames) {
		t.Fatalf("postgres migrations = %v, want the shared names %v", got, sharedNames)
	}
	overlay, err := fs.ReadDir(postgresMigrationFiles, "migrations/postgres")
	if err != nil {
		t.Fatal(err)
	}
	if len(overlay) == 0 {
		t.Fatal("no Postgres migration files")
	}
	for _, e := range overlay {
		if !slices.Contains(sharedNames, e.Name()) {
			t.Errorf("postgres file %s has no shared file of the same name", e.Name())
		}
		own, err := fs.ReadFile(postgresMigrationFiles, "migrations/postgres/"+e.Name())
		if err != nil {
			t.Fatal(err)
		}
		got, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(own) {
			t.Errorf("%s is not the Postgres file", e.Name())
		}
	}
}

// recDriver is a database/sql driver that records the SQL it is given and
// answers every query with one row holding 1. It checks the wiring of the
// Postgres store without a server: it stores nothing.
type recDriver struct {
	queries []string
}

type recConnector struct{ d *recDriver }

func (c recConnector) Connect(context.Context) (driver.Conn, error) { return recConn(c), nil }

func (c recConnector) Driver() driver.Driver { return nil }

type recConn struct{ d *recDriver }

func (c recConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }

func (c recConn) Close() error { return nil }

func (c recConn) Begin() (driver.Tx, error) { return recTx{}, nil }

func (c recConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return recTx{}, nil
}

func (c recConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.d.queries = append(c.d.queries, query)
	return driver.RowsAffected(1), nil
}

func (c recConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.d.queries = append(c.d.queries, query)
	return &recRows{}, nil
}

type recTx struct{}

func (recTx) Commit() error   { return nil }
func (recTx) Rollback() error { return nil }

// recRows holds one row with one column, the value 1.
type recRows struct{ done bool }

func (r *recRows) Columns() []string { return []string{"v"} }

func (r *recRows) Close() error { return nil }

func (r *recRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = int64(1)
	return nil
}

func TestPostgresStoreRunsTheSharedSQLWithNumberedPlaceholders(t *testing.T) {
	d := &recDriver{}
	db := sql.OpenDB(recConnector{d})
	s := &postgresStore{db: db}
	ctx := context.Background()
	use := func(tx Tx) error {
		q := tx.(*sqlTx).q
		if _, err := q.ExecContext(ctx, "UPDATE t SET a = ? WHERE b = ?", 1, 2); err != nil {
			return err
		}
		var v int
		if err := q.QueryRowContext(ctx, "SELECT ? + ?", 3, 4).Scan(&v); err != nil {
			return err
		}
		rows, err := q.QueryContext(ctx, "SELECT ?", 5)
		if err != nil {
			return err
		}
		return rows.Close()
	}
	if err := s.Write(ctx, use); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Read(ctx, use); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	want := []string{
		"UPDATE t SET a = $1 WHERE b = $2", "SELECT $1 + $2", "SELECT $1",
		"UPDATE t SET a = $1 WHERE b = $2", "SELECT $1 + $2", "SELECT $1",
	}
	if !slices.Equal(d.queries, want) {
		t.Fatalf("queries = %q, want %q", d.queries, want)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close takes the database over: it is closed after Close.
	if err := db.PingContext(ctx); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("ping after Close = %v, want the database closed", err)
	}
}

// overlayMigrations serves the shared files, each replaced by the file of the
// same name in own when there is one. A name only in own is served too.
func TestOverlayReplacesOnlyTheSharedNamesItHas(t *testing.T) {
	shared := map[string][]byte{
		"00001_init.sql":  []byte("shared 1"),
		"00002_other.sql": []byte("shared 2"),
	}
	own := map[string][]byte{
		"00001_init.sql": []byte("postgres 1"),
	}
	fsys := overlayMigrations(shared, own)
	want := map[string]string{
		"00001_init.sql":  "postgres 1", // replaced
		"00002_other.sql": "shared 2",   // not replaced
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %d, want %d", len(entries), len(want))
	}
	for name, body := range want {
		got, err := fs.ReadFile(fsys, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != body {
			t.Errorf("%s = %q, want %q", name, got, body)
		}
	}
	if _, err := fs.ReadFile(fsys, "00003_missing.sql"); err == nil {
		t.Error("a name in neither set was read")
	}
}

// mapFS serves the files of the map from the root and reports the rest as
// missing, as an fs.FS does.
func TestMapFSServesItsFiles(t *testing.T) {
	m := mapFS{"b.sql": []byte("bee"), "a.sql": []byte("ay")}
	f, err := m.Open("a.sql")
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil || info.Name() != "a.sql" || info.Size() != 2 || info.IsDir() || info.Mode().IsDir() ||
		info.Mode().Perm() != 0o444 || !info.ModTime().IsZero() || info.Sys() != nil {
		t.Fatalf("Stat = %v, %v", info, err)
	}
	body, err := io.ReadAll(f)
	if err != nil || string(body) != "ay" {
		t.Fatalf("read = %q, %v", body, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Open("missing.sql"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open missing = %v, want not exist", err)
	}
	if _, err := m.ReadFile("missing.sql"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadFile missing = %v, want not exist", err)
	}
	if _, err := m.ReadDir("sub"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadDir sub = %v, want not exist", err)
	}
	entries, err := m.ReadDir(".")
	if err != nil || len(entries) != 2 || entries[0].Name() != "a.sql" || entries[1].Name() != "b.sql" ||
		entries[0].IsDir() || entries[0].Type().IsDir() {
		t.Fatalf("ReadDir = %v, %v; want a.sql, b.sql sorted", entries, err)
	}
	// ReadFile returns a copy the caller may change.
	got, err := m.ReadFile("b.sql")
	if err != nil || string(got) != "bee" {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}
	got[0] = 'X'
	if string(m["b.sql"]) != "bee" {
		t.Fatal("ReadFile shares the stored bytes")
	}
}
