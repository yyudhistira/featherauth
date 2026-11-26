package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCopyFile writes a database.yaml-like file for db copy into a new directory
// and returns its path.
func writeCopyFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	writeConfig(t, dir, name, content)
	return filepath.Join(dir, name)
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// Usage errors exit 2 before any database is opened: a missing or repeated flag,
// an argument or flag that db copy does not take, and a file that names the wrong
// driver for its place: the source must be SQLite and the target Postgres.
func TestDBCopyUsageErrorsExitTwo(t *testing.T) {
	sqliteYAML := writeCopyFile(t, "database.yaml", "driver: sqlite\nsqlite:\n  path: /nonexistent/featherauth.db\n")
	postgresYAML := writeCopyFile(t, "database.yaml", "driver: postgres\npostgres:\n  host: 127.0.0.1\n  password_file: secrets/postgres_password\n")
	cases := []struct {
		name string
		args []string
	}{
		{"no subcommand", []string{"db"}},
		{"another subcommand", []string{"db", "dump"}},
		{"no flags", []string{"db", "copy"}},
		{"no target", []string{"db", "copy", "--from", sqliteYAML}},
		{"no source", []string{"db", "copy", "--to", postgresYAML}},
		{"an extra argument", []string{"db", "copy", "--from", sqliteYAML, "--to", postgresYAML, "extra"}},
		{"an unknown flag", []string{"db", "copy", "--from", sqliteYAML, "--to", postgresYAML, "--force"}},
		{"a repeated flag", []string{"db", "copy", "--from", sqliteYAML, "--from", postgresYAML, "--to", postgresYAML}},
		{"a postgres source", []string{"db", "copy", "--from", postgresYAML, "--to", postgresYAML}},
		{"a sqlite target", []string{"db", "copy", "--from", sqliteYAML, "--to", sqliteYAML}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := exec(t, map[string]string{}, c.args...)
			if r.code != 2 || !strings.Contains(r.stderr, "usage") || strings.Contains(r.stderr, "unknown command") {
				t.Fatalf("exit %d, stderr %q; want exit 2 and the db copy usage error", r.code, r.stderr)
			}
			if r.stdout != "" {
				t.Fatalf("stdout %q, want nothing", r.stdout)
			}
		})
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// A file that cannot be read, a database file that does not exist and a target
// file that fails validation exit 1, print what is wrong, and write nothing.
func TestDBCopyFilesThatCannotBeUsedExitOne(t *testing.T) {
	missingSource := filepath.Join(t.TempDir(), "none.yaml")
	noSQLite := writeCopyFile(t, "database.yaml", "driver: sqlite\nsqlite:\n  path: "+filepath.Join(t.TempDir(), "none.db")+"\n")
	badTarget := writeCopyFile(t, "database.yaml", "driver: postgres\n")
	// A target whose password file is missing, and one whose password file is there.
	noPasswordFile := writeCopyFile(t, "database.yaml", "driver: postgres\npostgres:\n  host: 127.0.0.1\n  password_file: nope\n")
	goodDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(goodDir, "pw"), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, goodDir, "database.yaml", "driver: postgres\npostgres:\n  host: 127.0.0.1\n  password_file: pw\n")
	goodTarget := filepath.Join(goodDir, "database.yaml")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"missing source file", []string{"db", "copy", "--from", missingSource, "--to", badTarget}, "none.yaml"},
		{"source database does not exist", []string{"db", "copy", "--from", noSQLite, "--to", goodTarget}, "none.db"},
		{"invalid target", []string{"db", "copy", "--from", noSQLite, "--to", badTarget}, "postgres.host"},
		{"unreadable password file", []string{"db", "copy", "--from", noSQLite, "--to", noPasswordFile}, "nope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := exec(t, map[string]string{}, c.args...)
			if r.code != 1 || !strings.Contains(r.stderr, c.want) {
				t.Fatalf("exit %d, stderr %q; want exit 1 naming %q", r.code, r.stderr, c.want)
			}
			if r.stdout != "" {
				t.Fatalf("stdout %q, want nothing", r.stdout)
			}
		})
	}
}
