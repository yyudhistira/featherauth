package store

import (
	"context"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/yyudhistira/featherauth/internal/config"
)

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
func TestCopyNamesItsDrivers(t *testing.T) {
	cases := []struct {
		name     string
		from, to config.DatabaseFile
	}{
		{"postgres source", config.DatabaseFile{Driver: "postgres"}, config.DatabaseFile{Driver: "postgres"}},
		{"sqlite target", config.DatabaseFile{Driver: "sqlite"}, config.DatabaseFile{Driver: "sqlite"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := CopySQLiteToPostgres(context.Background(), c.from, c.to, config.DatabaseSecrets{}); err == nil {
				t.Fatal("a copy between these drivers succeeded")
			}
		})
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
func TestCanonicalTextOfEachValue(t *testing.T) {
	cases := []struct {
		name    string
		v       any
		text    string
		null    bool
		wantErr bool
	}{
		{name: "null", v: nil, null: true},
		{name: "empty text", v: "", text: ""},
		{name: "text", v: "b@example.com", text: "b@example.com"},
		{name: "negative number", v: int64(-42), text: "-42"},
		{name: "true", v: true, text: "1"},
		{name: "false", v: false, text: "0"},
		{name: "bytes are refused", v: []byte("x"), wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text, null, err := canonicalText(c.v)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, want error %v", err, c.wantErr)
			}
			if err != nil {
				return
			}
			if null != c.null || string(text) != c.text {
				t.Fatalf("canonical text = %q null %v, want %q null %v", text, null, c.text, c.null)
			}
		})
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
func TestRowChecksumKeepsNullEmptyLengthsAndOrderApart(t *testing.T) {
	sum := func(rows ...[]any) [32]byte {
		t.Helper()
		d := newCopyDigest()
		for _, r := range rows {
			if err := d.add(r); err != nil {
				t.Fatal(err)
			}
		}
		return d.sum()
	}
	cases := []struct {
		name   string
		a, b   [][]any
		same   bool
		reason string
	}{
		{"null differs from empty text", [][]any{{nil}}, [][]any{{""}}, false, "a null is not an empty text"},
		{"lengths separate the columns", [][]any{{"ab", ""}}, [][]any{{"a", "b"}}, false, "the length of each text is part of it"},
		{"a boolean is its number", [][]any{{true}, {false}}, [][]any{{int64(1)}, {int64(0)}}, true, "a Postgres boolean and a SQLite integer of the same value agree"},
		{"row order matters", [][]any{{"a"}, {"b"}}, [][]any{{"b"}, {"a"}}, false, "the rows are read in key order, so the order is part of the sum"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sum(c.a...) == sum(c.b...); got != c.same {
				t.Fatalf("sums equal = %v, want %v: %s", got, c.same, c.reason)
			}
		})
	}
	d := newCopyDigest()
	if err := d.add([]any{"x"}); err != nil {
		t.Fatal(err)
	}
	if err := d.add([]any{"y"}); err != nil {
		t.Fatal(err)
	}
	if d.rows != 2 {
		t.Fatalf("rows = %d, want 2", d.rows)
	}
	if err := d.add([]any{[]byte("blob")}); err == nil {
		t.Fatal("a blob was added to the checksum")
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
func TestKeysCompareByBytes(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want int
	}{
		{"capital before lower case in bytes", []string{"B-user"}, []string{"a-user"}, -1},
		{"second column decides", []string{"a", "10"}, []string{"a", "2"}, -1},
		{"equal keys", []string{"x", "y"}, []string{"x", "y"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := compareKeys(c.a, c.b); got != c.want {
				t.Fatalf("compareKeys = %d, want %d", got, c.want)
			}
		})
	}
}

// Covers: FR-36 (part)
// Acceptance: Database copy (part)
// The copy takes its tables from the migrations, in the order they are created, so
// a table is copied after the tables it refers to; the version is the newest
// migration's. Only the Up part of a migration counts, and a file that does not
// start with a version, a directory without a table, and a missing directory are
// refused.
func TestMigrationSchemaFollowsTheMigrations(t *testing.T) {
	tables, version, err := migrationSchema(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"realms", "users", "identities", "auth_requests", "auth_codes", "callback_handoffs", "refresh_tokens", "audit_events", "provider_event_ids", "logout_notifications", "dpop_proofs", "sso_sessions", "rate_limits"}
	if !slices.Equal(tables, want) || version != 8 {
		t.Fatalf("schema = %v version %d, want %v version 8", tables, version, want)
	}

	fsys := fstest.MapFS{
		"migrations/00002_b.sql": {Data: []byte("-- +goose Up\nCREATE TABLE b (id TEXT PRIMARY KEY);\n-- +goose Down\nDROP TABLE b;\n")},
		"migrations/00001_a.sql": {Data: []byte("-- +goose Up\nCREATE TABLE a (id TEXT);\nCREATE TABLE a_two (id TEXT);\n-- +goose Down\nCREATE TABLE never (x);\n")},
		"migrations/notes.txt":   {Data: []byte("CREATE TABLE ignored (x);")},
	}
	tables, version, err = migrationSchema(fsys, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tables, []string{"a", "a_two", "b"}) || version != 2 {
		t.Fatalf("fixture schema = %v version %d", tables, version)
	}
	bad := fstest.MapFS{"migrations/x_bad.sql": {Data: []byte("CREATE TABLE t (x);")}}
	if _, _, err := migrationSchema(bad, "migrations"); err == nil {
		t.Fatal("a migration without a version number was accepted")
	}
	none := fstest.MapFS{"migrations/00001_none.sql": {Data: []byte("SELECT 1;")}}
	if _, _, err := migrationSchema(none, "migrations"); err == nil {
		t.Fatal("migrations with no table were accepted")
	}
	if _, _, err := migrationSchema(fsys, "missing"); err == nil {
		t.Fatal("a missing migration directory was accepted")
	}
}
