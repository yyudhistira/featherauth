package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
)

// copyTestSQLite opens a migrated SQLite store on a new file and closes it when the
// test ends.
func copyTestSQLite(t *testing.T) (Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "copy.db")
	s, err := Open(context.Background(), config.DatabaseFile{Driver: "sqlite", SQLite: config.SQLiteConfig{
		Path: path, BusyTimeout: config.Duration(5 * time.Second), JournalMode: "wal", ReadConnections: 2,
	}}, config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

// copyTestExec runs one statement in a write transaction of s.
func copyTestExec(t *testing.T, s Store, query string, args ...any) {
	t.Helper()
	if err := ExecForTest(context.Background(), s, query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// copyTestSeed writes rows of the tables a copy must carry: a null and an empty
// text, both boolean values, a set and an unset time, and a provider event.
func copyTestSeed(t *testing.T, s Store) {
	t.Helper()
	copyTestExec(t, s, `INSERT INTO realms (id, name, created_at) VALUES ('B-realm', 'main', 1)`)
	copyTestExec(t, s, `INSERT INTO users (realm_id, id, email, email_key, email_verified, name, disabled_at, created_at, updated_at)
		VALUES ('B-realm', 'B-user', 'b@example.com', 'b@example.com', 1, NULL, NULL, 1, 1)`)
	copyTestExec(t, s, `INSERT INTO users (realm_id, id, email, email_key, email_verified, name, disabled_at, created_at, updated_at)
		VALUES ('B-realm', 'a-user', NULL, NULL, 0, '', 5, 1, 1)`)
	copyTestExec(t, s, `INSERT INTO provider_event_ids (realm_id, provider, id_hash, expires_at) VALUES ('B-realm', 'google', 'h', 9)`)
	copyTestExec(t, s, `INSERT INTO audit_events (id, realm_id, actor, action, user_id, details, created_at)
		VALUES ('audit-1', 'B-realm', 'system', 'user.update', NULL, '{}', 1)`)
}

// copyTestSourceTables opens the SQLite database at path for the copy, checks it
// and returns its tables with the read transaction that holds them.
func copyTestSourceTables(t *testing.T, path string) (*sql.Tx, []sourceTable, error) {
	t.Helper()
	ctx := context.Background()
	src, err := openSQLiteSource(config.SQLiteConfig{Path: path, BusyTimeout: config.Duration(5 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = src.Close() })
	tx, err := src.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	names, version, err := migrationSchema(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	tables, err := sourceTables(ctx, tx, names, version)
	return tx, tables, err
}

// copyTestRun copies the tables of the source at srcPath into the SQLite store dst,
// through copyTables and one write transaction of dst.
func copyTestRun(t *testing.T, srcPath string, dst Store) ([]TableCopy, error) {
	t.Helper()
	srcTx, tables, err := copyTestSourceTables(t, srcPath)
	if err != nil {
		t.Fatal(err)
	}
	var out []TableCopy
	err = dst.Write(context.Background(), func(tx Tx) error {
		out = nil
		return copyTables(context.Background(), tx.(*sqlTx), srcTx, tables, &out)
	})
	return out, err
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// The rows of every table are written and read back with the same count and
// checksum, and the values kept as they were: null and empty texts stay apart.
func TestCopyTablesOntoSQLiteMatchesTheSource(t *testing.T) {
	src, srcPath := copyTestSQLite(t)
	copyTestSeed(t, src)
	dst, dstPath := copyTestSQLite(t)

	out, err := copyTestRun(t, srcPath, dst)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if len(out) != 13 {
		t.Fatalf("%d tables copied, want 13", len(out))
	}
	for _, tc := range out {
		if !tc.Match || tc.Rows != tc.TargetRows {
			t.Errorf("table %s: match %v, source %d, target %d", tc.Table, tc.Match, tc.Rows, tc.TargetRows)
		}
	}
	db, err := sql.Open("sqlite", dstPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var name sql.NullString
	if err := db.QueryRowContext(context.Background(), `SELECT name FROM users WHERE id = 'a-user'`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !name.Valid || name.String != "" {
		t.Fatalf("name of a-user = %v, want the empty text", name)
	}
	var verified int
	if err := db.QueryRowContext(context.Background(), `SELECT email_verified FROM users WHERE id = 'B-user'`).Scan(&verified); err != nil || verified != 1 {
		t.Fatalf("email_verified of B-user = %d, %v", verified, err)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A row that changes on the target before the commit is found by the check: the
// table is reported, the error is ErrCopyMismatch and the write rolls back.
func TestCopyTablesReportsAChangedRowAndRollsBack(t *testing.T) {
	src, srcPath := copyTestSQLite(t)
	copyTestSeed(t, src)
	dst, dstPath := copyTestSQLite(t)
	// The last table of the copy changes a row of users after its insert.
	copyTestExec(t, dst, `CREATE TRIGGER change_users AFTER INSERT ON provider_event_ids
		BEGIN UPDATE users SET name = 'changed' WHERE name IS NOT NULL; END`)

	out, err := copyTestRun(t, srcPath, dst)
	if !errors.Is(err, ErrCopyMismatch) {
		t.Fatalf("copy: %v, want ErrCopyMismatch", err)
	}
	differs := map[string]bool{}
	for _, tc := range out {
		differs[tc.Table] = !tc.Match
	}
	if !differs["users"] || differs["realms"] {
		t.Fatalf("differing tables = %v, want users only", differs)
	}
	db, err := sql.Open("sqlite", dstPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM users`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("users after the rollback = %d, %v; want 0", n, err)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// The source is refused when it has no schema version, another one, or a table the
// schema does not have.
func TestCopySourceVersionAndTablesAreChecked(t *testing.T) {
	ctx := context.Background()
	src, srcPath := copyTestSQLite(t)
	copyTestSeed(t, src)
	copyTestExec(t, src, `UPDATE goose_db_version SET is_applied = 0 WHERE version_id = (SELECT MAX(version_id) FROM goose_db_version WHERE is_applied = 1)`)
	if _, _, err := copyTestSourceTables(t, srcPath); !errors.Is(err, ErrSourceVersion) {
		t.Fatalf("another version: %v, want ErrSourceVersion", err)
	}

	plain := filepath.Join(t.TempDir(), "plain.db")
	plainDB, err := sql.Open("sqlite", plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plainDB.ExecContext(ctx, `CREATE TABLE realms (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	_ = plainDB.Close()
	if _, _, err := copyTestSourceTables(t, plain); !errors.Is(err, ErrSourceVersion) {
		t.Fatalf("no migration table: %v, want ErrSourceVersion", err)
	}

	extra, extraPath := copyTestSQLite(t)
	copyTestSeed(t, extra)
	copyTestExec(t, extra, `CREATE TABLE extra (id TEXT PRIMARY KEY)`)
	if _, _, err := copyTestSourceTables(t, extraPath); err == nil || !strings.Contains(err.Error(), "has tables") {
		t.Fatalf("an extra table: %v, want the tables named", err)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A table without a primary key cannot be copied in key order, and a table that does
// not exist has no columns.
func TestSourceTableNeedsAPrimaryKeyAndColumns(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "nokey.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, `CREATE TABLE nokey (a TEXT)`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, name := range []string{"nokey", "missing"} {
		if _, err := sqliteTable(ctx, tx, name); err == nil {
			t.Fatalf("sqliteTable(%s) succeeded", name)
		}
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// The copy never creates the source file: a missing file is an error.
func TestOpenSQLiteSourceNeedsAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.db")
	if _, err := openSQLiteSource(config.SQLiteConfig{Path: path, BusyTimeout: config.Duration(time.Second)}); err == nil {
		t.Fatal("a missing source opened")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("opening the source created the file")
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// Rows must come in strictly increasing key order by bytes, and keys must be text.
func TestEachRowChecksTheKeyOrder(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "keys.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, q := range []string{
		`CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)`,
		`INSERT INTO kv VALUES ('a', 'x'), ('b', 'y')`,
		`CREATE TABLE ints (id INTEGER PRIMARY KEY, v TEXT)`,
		`INSERT INTO ints VALUES (1, 'x')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	kv := sourceTable{name: "kv", cols: []string{"k", "v"}, key: []int{0}}
	noop := func([]any) error { return nil }
	if err := eachRow(ctx, db, kv, "SELECT k, v FROM kv ORDER BY k DESC", noop); err == nil || !strings.Contains(err.Error(), "key order") {
		t.Fatalf("rows out of order: %v", err)
	}
	if err := eachRow(ctx, db, kv, kv.selectSQL("", nil), noop); err != nil {
		t.Fatalf("rows in order: %v", err)
	}
	// An integer key is read in the order of its decimal text, as the checksum
	// orders it (9 sorts after 10): the copy's order, not the numeric one.
	if _, err := db.ExecContext(ctx, `INSERT INTO ints VALUES (9, 'z'), (10, 'w')`); err != nil {
		t.Fatal(err)
	}
	ints := sourceTable{name: "ints", cols: []string{"id", "v"}, key: []int{0}}
	intTypes := map[string]string{"id": "INTEGER", "v": "TEXT"}
	if err := eachRow(ctx, db, ints, ints.selectSQL("", intTypes), noop); err != nil {
		t.Fatalf("integer keys in decimal order: %v", err)
	}
	// A key of another type, a blob here, is still refused.
	if _, err := db.ExecContext(ctx, `CREATE TABLE blobs (k BLOB PRIMARY KEY, v TEXT); INSERT INTO blobs VALUES (X'01', 'x')`); err != nil {
		t.Fatal(err)
	}
	blobs := sourceTable{name: "blobs", cols: []string{"k", "v"}, key: []int{0}}
	if err := eachRow(ctx, db, blobs, blobs.selectSQL("", nil), noop); err == nil || !strings.Contains(err.Error(), "not text") {
		t.Fatalf("a blob key: %v", err)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A boolean is copied as true or false on a Postgres BOOL column and as its number
// elsewhere; a value that is no boolean, or a blob, is refused.
func TestTargetValueConvertsBooleansOnly(t *testing.T) {
	cases := []struct {
		name    string
		v       any
		typ     string
		want    any
		wantErr bool
	}{
		{name: "one is true on BOOL", v: int64(1), typ: "BOOL", want: true},
		{name: "zero is false on BOOL", v: int64(0), typ: "BOOL", want: false},
		{name: "two is not a boolean", v: int64(2), typ: "BOOL", wantErr: true},
		{name: "a number stays on INTEGER", v: int64(1), typ: "INTEGER", want: int64(1)},
		{name: "a text stays", v: "x", typ: "TEXT", want: "x"},
		{name: "a null stays", v: nil, typ: "BOOL", want: nil},
		{name: "a blob is refused", v: []byte("x"), typ: "BLOB", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := targetValue(c.v, c.typ)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, want error %v", err, c.wantErr)
			}
			if err == nil && got != c.want {
				t.Fatalf("value = %v (%T), want %v", got, got, c.want)
			}
		})
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A target that holds a row of a table is refused by refuseRows, and an empty one is
// not; a row the copy cannot place fails the insert with the table's name.
func TestTargetRowsAreRefusedAndInsertsFail(t *testing.T) {
	ctx := context.Background()
	src, srcPath := copyTestSQLite(t)
	copyTestSeed(t, src)
	dst, _ := copyTestSQLite(t)
	names, _, err := migrationSchema(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	checkRows := func() error {
		return dst.Write(ctx, func(tx Tx) error { return refuseRows(ctx, tx.(*sqlTx).q, names) })
	}
	if err := checkRows(); err != nil {
		t.Fatalf("an empty target: %v", err)
	}
	copyTestExec(t, dst, `INSERT INTO realms (id, name, created_at) VALUES ('other', 'main', 1)`)
	if err := checkRows(); !errors.Is(err, ErrTargetNotEmpty) {
		t.Fatalf("a target with a realm: %v, want ErrTargetNotEmpty", err)
	}

	// The realm row of the source has the id of the target's row, so its insert
	// violates the primary key and names the table.
	srcTx, tables, err := copyTestSourceTables(t, srcPath)
	if err != nil {
		t.Fatal(err)
	}
	var realms sourceTable
	for _, tb := range tables {
		if tb.name == "realms" {
			realms = tb
		}
	}
	err = dst.Write(ctx, func(tx Tx) error {
		types, err := columnTypes(ctx, tx.(*sqlTx).q, realms)
		if err != nil {
			return err
		}
		_, err = insertRows(ctx, tx.(*sqlTx).q, srcTx, realms, types)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "copy table realms") {
		t.Fatalf("the insert of a duplicate realm: %v", err)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// The source is checked before the target: a source at another version, or a
// missing source file, fails without the target being opened. The target here is
// an address that nothing listens on, so a connection would fail with another error.
func TestCopyChecksTheSourceBeforeTheTarget(t *testing.T) {
	src, srcPath := copyTestSQLite(t)
	copyTestSeed(t, src)
	copyTestExec(t, src, `UPDATE goose_db_version SET is_applied = 0 WHERE version_id = (SELECT MAX(version_id) FROM goose_db_version WHERE is_applied = 1)`)
	unreachable := config.DatabaseFile{Driver: "postgres", Postgres: config.PostgresConfig{
		Host: "127.0.0.1", Port: 1, Database: "x", User: "x", SSLMode: "disable", MaxOpenConns: 1, MaxIdleConns: 1,
	}}
	from := config.DatabaseFile{Driver: "sqlite", SQLite: config.SQLiteConfig{Path: srcPath, BusyTimeout: config.Duration(time.Second)}}
	if _, err := CopySQLiteToPostgres(context.Background(), from, unreachable, config.DatabaseSecrets{}); !errors.Is(err, ErrSourceVersion) {
		t.Fatalf("another version: %v, want ErrSourceVersion", err)
	}
	missing := from
	missing.SQLite.Path = filepath.Join(t.TempDir(), "absent.db")
	if _, err := CopySQLiteToPostgres(context.Background(), missing, unreachable, config.DatabaseSecrets{}); err == nil || errors.Is(err, ErrSourceVersion) {
		t.Fatalf("a missing source: %v", err)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// The target is checked for rows table by table; a table that does not exist yet
// holds none, so an empty target with no tables is accepted.
func TestRefuseRowsOfExistingTables(t *testing.T) {
	ctx := context.Background()
	dst, _ := copyTestSQLite(t)
	names, _, err := migrationSchema(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	check := func(names []string) error {
		return dst.Read(ctx, func(tx Tx) error { return refuseRowsOfExisting(ctx, tx.(*sqlTx).q, names) })
	}
	if err := check(names); err != nil {
		t.Fatalf("an empty target: %v", err)
	}
	if err := check([]string{"no_such_table"}); err != nil {
		t.Fatalf("a table that does not exist: %v", err)
	}
	copyTestExec(t, dst, `INSERT INTO realms (id, name, created_at) VALUES ('B-realm', 'main', 1)`)
	if err := check(names); !errors.Is(err, ErrTargetNotEmpty) {
		t.Fatalf("a target with a realm: %v, want ErrTargetNotEmpty", err)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A target that cannot be reached fails the copy at the first query of the target,
// before anything is written; the store opened on such a target fails to migrate.
func TestUnreachableTargetFailsBeforeAnyWrite(t *testing.T) {
	src, srcPath := copyTestSQLite(t)
	copyTestSeed(t, src)
	unreachable := config.DatabaseFile{Driver: "postgres", Postgres: config.PostgresConfig{
		Host: "127.0.0.1", Port: 1, Database: "x", User: "x", SSLMode: "disable", MaxOpenConns: 1, MaxIdleConns: 1,
		ConnMaxLifetime: config.Duration(time.Minute),
	}}
	from := config.DatabaseFile{Driver: "sqlite", SQLite: config.SQLiteConfig{Path: srcPath, BusyTimeout: config.Duration(time.Second)}}
	if _, err := CopySQLiteToPostgres(context.Background(), from, unreachable, config.DatabaseSecrets{}); err == nil || errors.Is(err, ErrSourceVersion) {
		t.Fatalf("copy to an unreachable target: %v", err)
	}
	if _, err := Open(context.Background(), unreachable, config.DatabaseSecrets{}); err == nil {
		t.Fatal("opening an unreachable Postgres succeeded")
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A target that holds a row is refused by the copy's own check, inside its write
// transaction, and nothing is written; a port that is not a port fails before the
// target is opened.
func TestCopyRefusesATargetWithRowsInsideTheWrite(t *testing.T) {
	src, srcPath := copyTestSQLite(t)
	copyTestSeed(t, src)
	dst, _ := copyTestSQLite(t)
	copyTestExec(t, dst, `INSERT INTO realms (id, name, created_at) VALUES ('other', 'main', 1)`)
	if _, err := copyTestRun(t, srcPath, dst); !errors.Is(err, ErrTargetNotEmpty) {
		t.Fatalf("copy onto a target with a realm: %v, want ErrTargetNotEmpty", err)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
func TestCopyRejectsAPortThatIsNoPort(t *testing.T) {
	src, srcPath := copyTestSQLite(t)
	copyTestSeed(t, src)
	bad := config.DatabaseFile{Driver: "postgres", Postgres: config.PostgresConfig{
		Host: "127.0.0.1", Port: 0, Database: "x", User: "x", SSLMode: "disable", MaxOpenConns: 1, MaxIdleConns: 1,
	}}
	from := config.DatabaseFile{Driver: "sqlite", SQLite: config.SQLiteConfig{Path: srcPath, BusyTimeout: config.Duration(time.Second)}}
	if _, err := CopySQLiteToPostgres(context.Background(), from, bad, config.DatabaseSecrets{}); err == nil || !strings.Contains(err.Error(), "postgres.port") {
		t.Fatalf("port 0: %v", err)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// The key order of a copy is the primary key column by column, with the byte
// collation on Postgres only; the existence of a table is read from the catalog of
// the driver.
func TestKeyOrderAndTableExistence(t *testing.T) {
	ctx := context.Background()
	tb := sourceTable{name: "kv", cols: []string{"a", "k", "v"}, key: []int{1, 0}}
	if got := tb.selectSQL("", nil); got != "SELECT a, k, v FROM kv ORDER BY k, a" {
		t.Fatalf("selectSQL = %q", got)
	}
	textKeys := map[string]string{"a": "TEXT", "k": "TEXT", "v": "TEXT"}
	if got := tb.selectSQL(keyCollation(pgRebind{}), textKeys); got != `SELECT a, k, v FROM kv ORDER BY k COLLATE "C", a COLLATE "C"` {
		t.Fatalf("selectSQL on Postgres = %q", got)
	}
	if keyCollation(&sql.Tx{}) != "" {
		t.Fatal("a SQLite transaction takes no collation")
	}
	// An integer key is ordered by its decimal text, with the byte collation on
	// Postgres (a collation on bigint itself is refused). Text keys get the clause.
	rl := sourceTable{name: "rate_limits", cols: []string{"key", "window_start", "count"}, key: []int{0, 1}}
	rlTypes := map[string]string{"key": "TEXT", "window_start": "INT8", "count": "INT8"}
	want := `SELECT key, window_start, count FROM rate_limits ORDER BY key COLLATE "C", CAST(window_start AS TEXT) COLLATE "C"`
	if got := rl.selectSQL(keyCollation(pgRebind{}), rlTypes); got != want {
		t.Fatalf("selectSQL with a bigint key = %q, want %q", got, want)
	}
	dst, _ := copyTestSQLite(t)
	for name, want := range map[string]bool{"realms": true, "no_such_table": false} {
		var got bool
		if err := dst.Read(ctx, func(tx Tx) error {
			var err error
			got, err = tableExists(ctx, tx.(*sqlTx).q, name)
			return err
		}); err != nil || got != want {
			t.Fatalf("tableExists(%s) = %v, %v; want %v", name, got, err, want)
		}
	}
}

// Covers: FR-36 (part), FR-53 (part)
// Acceptance: Database copy (part)
//
// A copy carries the rate limit windows: rate_limits has an integer key column,
// and the key order of a copy is the bytes of the key's canonical text (the
// decimal of a number), on both sides. The windows 9, 10 and 100 of one key sort
// 10, 100, 9 in bytes and 9, 10, 100 as numbers, so the copy must read them in
// the one order it checks; the rows and the checksum of each table must match.
func TestCopyCarriesRateLimitWindows(t *testing.T) {
	src, srcPath := copyTestSQLite(t)
	copyTestSeed(t, src)
	for _, w := range []int{9, 10, 100} {
		copyTestExec(t, src, `INSERT INTO rate_limits (key, window_start, count) VALUES ('203.0.113.7', ?, ?)`, w, w)
	}
	dst, _ := copyTestSQLite(t)

	out, err := copyTestRun(t, srcPath, dst)
	if err != nil {
		t.Fatalf("copy with rate limit windows: %v", err)
	}
	var found bool
	for _, tc := range out {
		if tc.Table != "rate_limits" {
			continue
		}
		found = true
		if tc.Rows != 3 || tc.TargetRows != 3 || !tc.Match {
			t.Fatalf("rate_limits: source %d, target %d, match %v; want 3, 3, true", tc.Rows, tc.TargetRows, tc.Match)
		}
	}
	if !found {
		t.Fatal("the copy does not report rate_limits")
	}
}
