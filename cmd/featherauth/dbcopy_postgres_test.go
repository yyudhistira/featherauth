//go:build postgres

package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// sqliteDatabaseFile writes the database.yaml of the SQLite database at path into
// a new directory and returns the file's path.
func sqliteDatabaseFile(t *testing.T, path string) string {
	t.Helper()
	return writeCopyFile(t, "database.yaml", "driver: sqlite\nsqlite:\n  path: "+path+"\n")
}

// postgresDatabaseFile writes the database.yaml of the Postgres database called
// database on srv into dir, with its password file, and returns the file's path.
func postgresDatabaseFile(t *testing.T, dir string, srv testutil.PostgresServer, database string) string {
	t.Helper()
	writeConfig(t, dir, "secrets/postgres_password", srv.Password+"\n")
	writeConfig(t, dir, "database.yaml", fmt.Sprintf("driver: postgres\npostgres:\n  host: %s\n  port: %d\n  database: %s\n  user: %s\n  password_file: secrets/postgres_password\n  sslmode: disable\n",
		srv.Host, srv.Port, database, srv.User))
	return filepath.Join(dir, "database.yaml")
}

// copyLines reads the output of a successful db copy: one "<table> <rows> ok" line
// for each table and "copied" last. It returns the rows of each table.
func copyLines(t *testing.T, stdout string) map[string]int64 {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 2 || lines[len(lines)-1] != "copied" {
		t.Fatalf("output %q does not end with copied", stdout)
	}
	out := map[string]int64{}
	for _, l := range lines[:len(lines)-1] {
		var name, status string
		var rows int64
		if n, err := fmt.Sscanf(l, "%s %d %s", &name, &rows, &status); err != nil || n != 3 || status != "ok" {
			t.Fatalf("table line %q, want <table> <rows> ok", l)
		}
		out[name] = rows
	}
	return out
}

// assertNoPassword fails when the output of a command holds the password of srv.
func assertNoPassword(t *testing.T, srv testutil.PostgresServer, r result) {
	t.Helper()
	if strings.Contains(r.stdout, srv.Password) || strings.Contains(r.stderr, srv.Password) {
		t.Fatal("the output of db copy holds the Postgres password")
	}
}

// copyUserID returns the id of the user with the email ann@example.com, as user list
// prints it for the configuration directory dir.
func copyUserID(t *testing.T, dir string) string {
	t.Helper()
	r := exec(t, map[string]string{"FEATHERAUTH_CONFIG_DIR": dir}, "user", "list", "main", "--email", "ann@example.com")
	var users []map[string]any
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &users) != nil || len(users) != 1 {
		t.Fatalf("user list: %+v", r)
	}
	return fmt.Sprint(users[0]["id"])
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A seeded SQLite service is copied to an empty Postgres database: one line for
// each table of the schema, the rows of each table on Postgres as the copy said,
// and copied last. A service started on the copy answers the refresh of a token
// the SQLite service issued, and a new login of the same user.
func TestDBCopyServiceAnswersTheSameLoginAndRefresh(t *testing.T) {
	e := server.New(t, server.WithServerSetting("rate_limit:\n  per_ip_per_minute: 100\n"))
	testutil.SeedEveryTable(t, e.Store)
	e.Mocks["corp"].SetUser(mockidp.User{Sub: "77", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
	grant := e.Exchange(t, server.ClientQuery, e.NewClient().Login(t, server.Authorize(server.ClientQuery, "corp")))
	if grant.RefreshToken == "" {
		t.Fatal("the SQLite service issued no refresh token")
	}

	src := sqliteDatabaseFile(t, e.DatabasePath)
	before := copyUserID(t, filepath.Dir(src))

	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	dst := postgresDatabaseFile(t, e.ConfigDir(), srv, pg.Database)
	r := exec(t, map[string]string{"FEATHERAUTH_CONFIG_DIR": e.ConfigDir()}, "db", "copy", "--from", src, "--to", dst)
	if r.code != 0 {
		t.Fatalf("db copy: %+v", r)
	}
	assertNoPassword(t, srv, r)
	copied := copyLines(t, r.stdout)
	rows := testutil.RowCounts(t, srv.Connect(t, pg.Database))
	if want := testutil.SQLiteTables(t, e.DatabasePath); !slices.Equal(slices.Sorted(maps.Keys(copied)), want) {
		t.Fatalf("copy lines name %v, the schema has %v", slices.Sorted(maps.Keys(copied)), want)
	}
	for table, n := range copied {
		if rows[table] != n {
			t.Fatalf("table %s: the copy said %d rows, Postgres has %d", table, n, rows[table])
		}
	}

	s := startServiceIn(t, e, e.ConfigDir(), e.Clock)
	if status, m := s.refresh(server.ClientQuery, grant.RefreshToken); status != 200 || m["refresh_token"] == nil {
		t.Fatalf("refresh on the copy = %d %v", status, m)
	}
	code, errCode := postgresLogin(t, s, e)
	if code == "" {
		t.Fatalf("login on the copy: %q", errCode)
	}
	if status, tokens := postgresExchange(t, s, code); status != 200 || tokens["refresh_token"] == nil {
		t.Fatalf("code exchange on the copy = %d %v", status, tokens)
	}
	if after := copyUserID(t, e.ConfigDir()); after != before {
		t.Fatalf("the login on the copy is user %s, on SQLite it was %s", after, before)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A target that holds rows exits 1 with nothing written, and its rows do not change.
func TestDBCopyRefusesANonEmptyTarget(t *testing.T) {
	st, path := testutil.NewStoreFile(t)
	testutil.SeedEveryTable(t, st)
	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	dir := t.TempDir()
	src := sqliteDatabaseFile(t, path)
	dst := postgresDatabaseFile(t, dir, srv, pg.Database)
	env := map[string]string{"FEATHERAUTH_CONFIG_DIR": dir}
	if r := exec(t, env, "db", "copy", "--from", src, "--to", dst); r.code != 0 {
		t.Fatalf("first copy: %+v", r)
	}
	db := srv.Connect(t, pg.Database)
	before := testutil.RowCounts(t, db)

	r := exec(t, env, "db", "copy", "--from", src, "--to", dst)
	if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, "not empty") {
		t.Fatalf("second copy: %+v, want exit 1 naming the non-empty target", r)
	}
	assertNoPassword(t, srv, r)
	if after := testutil.RowCounts(t, db); !maps.Equal(before, after) {
		t.Fatalf("the refused copy changed the target: %v, was %v", after, before)
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A source at another schema version exits 1 before anything is written: the
// target gets no table.
func TestDBCopyRefusesAnotherSchemaVersion(t *testing.T) {
	st, path := testutil.NewStoreFile(t)
	testutil.SeedEveryTable(t, st)
	testutil.UnapplyNewestSQLiteMigration(t, path)
	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	dir := t.TempDir()
	r := exec(t, map[string]string{"FEATHERAUTH_CONFIG_DIR": dir}, "db", "copy",
		"--from", sqliteDatabaseFile(t, path), "--to", postgresDatabaseFile(t, dir, srv, pg.Database))
	if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, "schema version") {
		t.Fatalf("copy: %+v, want exit 1 naming the schema version", r)
	}
	assertNoPassword(t, srv, r)
	if counts := testutil.RowCounts(t, srv.Connect(t, pg.Database)); len(counts) != 0 {
		t.Fatalf("the refused copy created tables on the target: %v", counts)
	}
}

// changeUsersTrigger changes a row of users when the last table of the copy takes
// its first row: the rows of users are written before that, so the change is made
// to the target after the copy wrote them and before the commit. The trigger is
// installed by this test on a migrated target only; the copy has no hook.
const changeUsersTrigger = `CREATE FUNCTION ft_change_users() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	UPDATE users SET name = 'changed by the test' WHERE name IS NOT NULL;
	RETURN NEW;
END
$$`

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A row of the target that changes before the commit makes the check fail: the
// table that differs is named, the target is rolled back and the command exits 1.
func TestDBCopyRollsBackAChangedRow(t *testing.T) {
	st, path := testutil.NewStoreFile(t)
	testutil.SeedEveryTable(t, st)
	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	ctx := t.Context()

	migrated, err := store.NewPostgres(ctx, srv.Connect(t, pg.Database))
	if err != nil {
		t.Fatal(err)
	}
	_ = migrated.Close()
	db := srv.Connect(t, pg.Database)
	if _, err := db.ExecContext(ctx, changeUsersTrigger); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TRIGGER ft_change_users AFTER INSERT ON provider_event_ids FOR EACH ROW EXECUTE FUNCTION ft_change_users()`); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	r := exec(t, map[string]string{"FEATHERAUTH_CONFIG_DIR": dir}, "db", "copy",
		"--from", sqliteDatabaseFile(t, path), "--to", postgresDatabaseFile(t, dir, srv, pg.Database))
	if r.code != 1 || strings.Contains(r.stdout, "copied") {
		t.Fatalf("copy: %+v, want exit 1 without copied", r)
	}
	assertNoPassword(t, srv, r)
	if !slices.ContainsFunc(strings.Split(r.stdout, "\n"), func(l string) bool {
		return strings.HasPrefix(l, "users ") && strings.HasSuffix(l, " differs")
	}) {
		t.Fatalf("output %q does not name users as differing", r.stdout)
	}
	for table, n := range testutil.RowCounts(t, db) {
		if table != "goose_db_version" && n != 0 {
			t.Fatalf("the rolled back copy left %d rows in %s", n, table)
		}
	}
}

// The Database copy row of the acceptance table. Its conditions are run here: the
// usage errors and the files that cannot be used, the copy of a seeded database
// with the service on the copy, a non-empty target, another schema version, and a
// row that changes before the commit.
//
// Covers: FR-36
// Acceptance: Database copy
func TestDatabaseCopyRow(t *testing.T) {
	cases := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"usage errors", TestDBCopyUsageErrorsExitTwo},
		{"files that cannot be used", TestDBCopyFilesThatCannotBeUsedExitOne},
		{"copy and the service on the copy", TestDBCopyServiceAnswersTheSameLoginAndRefresh},
		{"non-empty target", TestDBCopyRefusesANonEmptyTarget},
		{"another schema version", TestDBCopyRefusesAnotherSchemaVersion},
		{"changed row", TestDBCopyRollsBackAChangedRow},
	}
	for _, c := range cases {
		t.Run(c.name, c.fn)
	}
}
