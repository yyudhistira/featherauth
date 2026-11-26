package store_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

func dbConfig(path string) config.DatabaseFile {
	return testutil.DatabaseConfig(path)
}

// rawDB opens the file with a plain connection to inspect the schema.
func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestMigrationsApplyAndRerunAsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.db")
	ctx := context.Background()

	s, err := store.Open(ctx, dbConfig(path), config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	var n1 int
	if err := db.QueryRow(`SELECT COUNT(*) FROM goose_db_version`).Scan(&n1); err != nil {
		t.Fatal(err)
	}
	if n1 < 2 { // goose's own zero row plus at least one migration
		t.Fatalf("version rows = %d, want at least 2", n1)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = store.Open(ctx, dbConfig(path), config.DatabaseSecrets{})
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer s.Close()
	var n2 int
	if err := db.QueryRow(`SELECT COUNT(*) FROM goose_db_version`).Scan(&n2); err != nil {
		t.Fatal(err)
	}
	if n1 != n2 {
		t.Fatalf("version rows changed from %d to %d on re-run", n1, n2)
	}
}

func TestOpenRejectsUnknownDriver(t *testing.T) {
	cfg := dbConfig(filepath.Join(t.TempDir(), "f.db"))
	cfg.Driver = "mysql"
	if _, err := store.Open(context.Background(), cfg, config.DatabaseSecrets{}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestBackupWritesConsistentCopy(t *testing.T) {
	s := testutil.NewStore(t)
	ctx := context.Background()
	insertRealm(t, s, "r", "n")
	dest := filepath.Join(t.TempDir(), "b.db")
	if err := s.Backup(ctx, dest); err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, dest)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM realms`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("backup realms = %d, err %v", n, err)
	}
	if err := s.Backup(ctx, dest); err == nil {
		t.Fatal("backup over an existing file must fail")
	}
}

func TestClosedStoreIsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.db")
	s, err := store.Open(context.Background(), dbConfig(path), config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("ping on a closed store succeeded")
	}
}

// designPrimaryKeys is the primary key of each Data model table, in key order.
var designPrimaryKeys = map[string]string{
	"realms": "id", "users": "id", "identities": "id", "auth_requests": "id",
	"auth_codes": "code_hash", "callback_handoffs": "id_hash", "refresh_tokens": "id", "audit_events": "id",
	"logout_notifications": "id",
	"provider_event_ids":   "realm_id,provider,id_hash",
	"dpop_proofs":          "proof_hash",
	"sso_sessions":         "id_hash",
	"rate_limits":          "key,window_start",
}

// designIndexes lists the indexes of the Data model, as "unique:", "index:" or
// "unique-partial:" and their columns in key order. Primary keys are not listed.
var designIndexes = map[string][]string{
	"realms":               {"unique:name"},
	"users":                {"index:realm_id,email_key", "unique-partial:realm_id,email_key"},
	"identities":           {"unique:realm_id,provider,provider_sub"},
	"refresh_tokens":       {"index:session_id", "index:user_id", "unique:token_hash"},
	"audit_events":         {"index:realm_id,created_at"},
	"logout_notifications": {"index:next_attempt_at"},
	// One handoff for each login (SEC-23).
	"callback_handoffs": {"unique:auth_request_id"},
	"sso_sessions":      {"index:user_id"},
}

// indexedTables are the tables whose indexes designIndexes lists.
var indexedTables = []string{"realms", "users", "identities", "auth_requests", "auth_codes", "callback_handoffs", "refresh_tokens", "audit_events", "logout_notifications", "sso_sessions"}

// designTable is one row of the Data model table of docs/DESIGN.md.
type designTable struct {
	columns  []string
	nullable map[string]bool
}

var backtick = regexp.MustCompile("^`([a-z_]+)`")

func parseDataModel(t *testing.T) map[string]designTable {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "DESIGN.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(b), "\n## Data model\n")
	if !ok {
		t.Fatal("no Data model section")
	}
	section, _, _ := strings.Cut(rest, "\n## ")
	out := map[string]designTable{}
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(line, "|")
		name := strings.Trim(strings.TrimSpace(cells[1]), "`")
		dt := designTable{nullable: map[string]bool{}}
		for _, item := range splitTop(strings.TrimSpace(cells[2])) {
			m := backtick.FindStringSubmatch(item)
			if m == nil {
				t.Fatalf("cannot parse column %q of %s", item, name)
			}
			dt.columns = append(dt.columns, m[1])
			if strings.HasPrefix(strings.TrimPrefix(item, m[0]), " (nullable") {
				dt.nullable[m[1]] = true
			}
		}
		out[name] = dt
	}
	return out
}

// splitTop splits on commas outside parentheses.
func splitTop(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

// Covers: FR-35 (part), FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
func TestSchemaMatchesDesign(t *testing.T) {
	design := parseDataModel(t)
	if len(design) != 13 {
		t.Fatalf("parsed %d tables from the design, want 13", len(design))
	}
	path := filepath.Join(t.TempDir(), "f.db")
	s, err := store.Open(context.Background(), dbConfig(path), config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	db := rawDB(t, path)

	var tables []string
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'goose_%'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	_ = rows.Close()
	sort.Strings(tables)
	var want []string
	for n := range design {
		want = append(want, n)
	}
	sort.Strings(want)
	if strings.Join(tables, ",") != strings.Join(want, ",") {
		t.Fatalf("tables = %v, want %v", tables, want)
	}

	for name, dt := range design {
		got := map[string]bool{} // column -> nullable
		r, err := db.Query(`SELECT name, "notnull", pk FROM pragma_table_info(?)`, name)
		if err != nil {
			t.Fatal(err)
		}
		var order []string
		for r.Next() {
			var c string
			var nn, pk int
			_ = r.Scan(&c, &nn, &pk)
			got[c] = nn == 0 && pk == 0
			order = append(order, c)
		}
		_ = r.Close()
		sort.Strings(order)
		wantCols := append([]string(nil), dt.columns...)
		sort.Strings(wantCols)
		if strings.Join(order, ",") != strings.Join(wantCols, ",") {
			t.Errorf("%s columns = %v, want %v", name, order, wantCols)
			continue
		}
		for _, c := range dt.columns {
			wantNull := dt.nullable[c]
			if got[c] != wantNull {
				t.Errorf("%s.%s nullable = %v, want %v", name, c, got[c], wantNull)
			}
		}
	}

	// Primary keys and indexes, from the Constraints column.
	for tbl, col := range designPrimaryKeys {
		var got string
		if err := db.QueryRow(`SELECT group_concat(name) FROM pragma_table_info(?) WHERE pk > 0`, tbl).Scan(&got); err != nil || got != col {
			t.Errorf("%s primary key = %q (%v), want %q", tbl, got, err, col)
		}
	}
	for _, tbl := range indexedTables {
		r, err := db.Query(`SELECT il.name, il."unique", il.partial, il.origin FROM pragma_index_list(?) il`, tbl)
		if err != nil {
			t.Fatal(err)
		}
		type idx struct {
			name           string
			unique, partia bool
			origin         string
		}
		var list []idx
		for r.Next() {
			var i idx
			_ = r.Scan(&i.name, &i.unique, &i.partia, &i.origin)
			list = append(list, i)
		}
		_ = r.Close()
		var got []string
		for _, i := range list {
			if i.origin == "pk" {
				continue
			}
			var cols string
			if err := db.QueryRow(`SELECT group_concat(name) FROM (SELECT name FROM pragma_index_info(?) ORDER BY seqno)`, i.name).Scan(&cols); err != nil {
				t.Fatal(err)
			}
			kind := "index"
			switch {
			case i.unique && i.partia:
				kind = "unique-partial"
			case i.unique:
				kind = "unique"
			}
			got = append(got, kind+":"+cols)
		}
		sort.Strings(got)
		w := append([]string(nil), designIndexes[tbl]...)
		sort.Strings(w)
		if strings.Join(got, ";") != strings.Join(w, ";") {
			t.Errorf("%s indexes = %v, want %v", tbl, got, w)
		}
	}

	// Cascade on user delete.
	var fk string
	if err := db.QueryRow(`SELECT "table" || ':' || on_delete FROM pragma_foreign_key_list('identities') WHERE "from" = 'user_id'`).Scan(&fk); err != nil || fk != "users:CASCADE" {
		t.Errorf("identities.user_id foreign key = %q (%v), want users:CASCADE", fk, err)
	}
	// A browser session is deleted with its user (FR-45).
	if err := db.QueryRow(`SELECT "table" || ':' || on_delete FROM pragma_foreign_key_list('sso_sessions') WHERE "from" = 'user_id'`).Scan(&fk); err != nil || fk != "users:CASCADE" {
		t.Errorf("sso_sessions.user_id foreign key = %q (%v), want users:CASCADE", fk, err)
	}
}

func insertRealm(t *testing.T, s store.Store, id, name string) {
	t.Helper()
	if err := store.ExecForTest(context.Background(), s, `INSERT INTO realms (id, name, created_at) VALUES (?, ?, 1)`, id, name); err != nil {
		t.Fatal(err)
	}
}

func TestOpenWithSpecialCharactersInPath(t *testing.T) {
	// Covers: FR-25 (part)
	// Acceptance: Database file (part)
	dir := filepath.Join(t.TempDir(), "a b%c#d?e%20f")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "f g%h#i?j.db")
	ctx := context.Background()
	s, err := store.Open(ctx, dbConfig(path), config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database not created at the configured path: %v", err)
	}
	if err := store.ExecForTest(ctx, s, `INSERT INTO realms (id, name, created_at) VALUES ('r', 'n', 1)`); err != nil {
		t.Fatal(err)
	}
	if n := countRealms(t, s, true); n != 1 {
		t.Fatalf("read connection sees %d realms, want 1", n)
	}
}

// Covers: FR-16 (part)
//
// Under load the single write connection is held by a queue of requests; the
// readiness ping must not wait behind them (found by the peak load run, where
// /readyz answered 503 after the health check's 3 seconds).
func TestPingDoesNotWaitForTheWriteConnection(t *testing.T) {
	s, err := store.Open(context.Background(), dbConfig(filepath.Join(t.TempDir(), "f.db")), config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	held, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.Write(context.Background(), func(store.Tx) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = s.Ping(ctx)
	close(release)
	if werr := <-done; werr != nil {
		t.Fatal(werr)
	}
	if err != nil {
		t.Fatalf("ping while the write connection is busy: %v", err)
	}
}

// Covers: SEC-43 (part), SEC-47 (part)
//
// A failure of the database comes back from the sealed token queries as an error.
func TestSealedTokenQueriesReportDatabaseErrors(t *testing.T) {
	ctx := context.Background()
	s := testutil.NewStore(t)
	if err := store.ExecForTest(ctx, s, `DROP TABLE identities`); err != nil {
		t.Fatal(err)
	}
	err := s.Read(ctx, func(tx store.Tx) error {
		_, err := tx.Identities().SealedBy(ctx, "r1", "aaaaaaaa")
		return err
	})
	if err == nil {
		t.Error("SealedBy on a missing table succeeded")
	}
	err = s.Write(ctx, func(tx store.Tx) error {
		_, err := tx.Identities().ReplaceProviderToken(ctx, "r1", "i1", "a", "b")
		return err
	})
	if err == nil {
		t.Error("ReplaceProviderToken on a missing table succeeded")
	}
}

// Covers: SEC-43 (part), SEC-47 (part)
//
// A sealed identity logs its ids and provider, never the stored value or the
// subject, directly or inside a map (as audit details are).
func TestSealedIdentityLogsNoValue(t *testing.T) {
	si := store.SealedIdentity{ID: "i1", RealmID: "r1", UserID: "u1", Provider: "apple", Subject: "subject-xyz", Value: "aaaaaaaa.secret-value"}
	var buf strings.Builder
	l := logx.New(&buf, 0, clock.NewFake(time.Unix(0, 0)))
	l.Info("direct", "ident", si)
	l.Info("nested", "details", map[string]any{"ident": si})
	out := buf.String()
	for _, bad := range []string{"subject-xyz", "secret-value"} {
		if strings.Contains(out, bad) {
			t.Fatalf("log holds %q: %s", bad, out)
		}
	}
	if !strings.Contains(out, "u1") || !strings.Contains(out, "apple") {
		t.Fatalf("log lacks the ids: %s", out)
	}
}
