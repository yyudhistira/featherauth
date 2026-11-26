//go:build postgres

package store_test

import (
	"database/sql"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/storetest"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// Covers: FR-35 (part)
// Acceptance: Postgres store
// Acceptance: Postgres concurrency (part)
// The contract suite of every store, run on a fresh Postgres schema. It includes
// the store's concurrency cases (the verified email race, the forced deadlocks,
// the unique violations), which are the store half of Postgres concurrency only;
// the row is closed by TestDriverCasesPostgres, which runs them with the token
// service's cases.
// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
func TestPostgresStoreContract(t *testing.T) {
	storetest.Run(t, testutil.NewPostgresStore)
}

// postgresBigint lists the Data model columns that hold times (UTC Unix seconds),
// a count of seconds, a small count, or a rate limit window and its request count;
// they are bigint on Postgres. email_verified is boolean.
var postgresBigint = map[string]bool{
	"created_at": true, "updated_at": true, "disabled_at": true, "expires_at": true,
	"used_at": true, "revoked_at": true, "session_started_at": true, "auth_time": true,
	"max_age": true, "attempts": true, "next_attempt_at": true, "last_used_at": true,
	"window_start": true, "count": true,
}

// Covers: FR-35 (part), FR-45 (part), SEC-37 (part)
// Acceptance: Postgres store
// Acceptance: Single sign-on start (part)
// The migrations of Postgres create the tables, columns, keys and indexes of the
// Data model, as the SQLite test checks for SQLite, with the nearest types.
func TestPostgresSchemaMatchesDesign(t *testing.T) {
	ctx := t.Context()
	db := testutil.NewPostgresDB(t)
	s, err := store.NewPostgres(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	design := parseDataModel(t)
	if len(design) != 13 {
		t.Fatalf("parsed %d tables from the design, want 13", len(design))
	}

	var tables []string
	for _, row := range queryStrings(t, db, `SELECT table_name FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' AND table_name NOT LIKE 'goose%'`) {
		tables = append(tables, row[0])
	}
	sort.Strings(tables)
	var want []string
	for n := range design {
		want = append(want, n)
	}
	sort.Strings(want)
	if strings.Join(tables, ",") != strings.Join(want, ",") {
		t.Fatalf("tables = %v, want %v", tables, want)
	}

	// Columns: names, nullability and types.
	got := map[string]map[string][]string{} // table -> column -> {type, nullable}
	for _, row := range queryStrings(t, db, `SELECT table_name, column_name, data_type, is_nullable
		FROM information_schema.columns WHERE table_schema = current_schema()`) {
		if got[row[0]] == nil {
			got[row[0]] = map[string][]string{}
		}
		got[row[0]][row[1]] = []string{row[2], row[3]}
	}
	for name, dt := range design {
		cols := got[name]
		var names []string
		for c := range cols {
			names = append(names, c)
		}
		sort.Strings(names)
		wantCols := append([]string(nil), dt.columns...)
		sort.Strings(wantCols)
		if strings.Join(names, ",") != strings.Join(wantCols, ",") {
			t.Errorf("%s columns = %v, want %v", name, names, wantCols)
			continue
		}
		for _, c := range dt.columns {
			wantType := "text"
			switch {
			case c == "email_verified":
				wantType = "boolean"
			case postgresBigint[c]:
				wantType = "bigint"
			}
			if cols[c][0] != wantType {
				t.Errorf("%s.%s type = %s, want %s", name, c, cols[c][0], wantType)
			}
			if nullable := cols[c][1] == "YES"; nullable != dt.nullable[c] {
				t.Errorf("%s.%s nullable = %v, want %v", name, c, nullable, dt.nullable[c])
			}
		}
	}

	// Primary keys, in key order.
	for tbl, col := range designPrimaryKeys {
		var pk string
		err := db.QueryRowContext(ctx, `SELECT string_agg(a.attname, ',' ORDER BY k.ord)
			FROM pg_index i
			JOIN pg_class t ON t.oid = i.indrelid
			CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
			JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
			WHERE t.relname = $1 AND t.relnamespace = current_schema()::regnamespace AND i.indisprimary`, tbl).Scan(&pk)
		if err != nil || pk != col {
			t.Errorf("%s primary key = %q (%v), want %q", tbl, pk, err, col)
		}
	}

	// Indexes that are not primary keys: kind and columns in key order.
	indexes := map[string][]string{}
	for _, row := range queryStrings(t, db, `SELECT t.relname, i.indisunique, i.indpred IS NOT NULL, cols.list
		FROM pg_index i
		JOIN pg_class t ON t.oid = i.indrelid
		JOIN LATERAL (
			SELECT string_agg(a.attname, ',' ORDER BY k.ord) AS list
			FROM unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
			JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
		) cols ON true
		WHERE t.relnamespace = current_schema()::regnamespace AND NOT i.indisprimary`) {
		kind := "index"
		switch {
		case row[1] == "true" && row[2] == "true":
			kind = "unique-partial"
		case row[1] == "true":
			kind = "unique"
		}
		indexes[row[0]] = append(indexes[row[0]], kind+":"+row[3])
	}
	for _, tbl := range indexedTables {
		list := append([]string(nil), indexes[tbl]...)
		sort.Strings(list)
		w := append([]string(nil), designIndexes[tbl]...)
		sort.Strings(w)
		if strings.Join(list, ";") != strings.Join(w, ";") {
			t.Errorf("%s indexes = %v, want %v", tbl, list, w)
		}
	}

	// Cascade on user delete.
	var fk string
	if err := db.QueryRowContext(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = 'identities'::regclass AND contype = 'f' AND pg_get_constraintdef(oid) LIKE 'FOREIGN KEY (user_id)%'`).Scan(&fk); err != nil {
		t.Fatalf("identities.user_id foreign key: %v", err)
	}
	if want := "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"; fk != want {
		t.Errorf("identities.user_id foreign key = %q, want %q", fk, want)
	}
	// A browser session is deleted with its user (FR-45).
	if err := db.QueryRowContext(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = 'sso_sessions'::regclass AND contype = 'f' AND pg_get_constraintdef(oid) LIKE 'FOREIGN KEY (user_id)%'`).Scan(&fk); err != nil {
		t.Fatalf("sso_sessions.user_id foreign key: %v", err)
	}
	if want := "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"; fk != want {
		t.Errorf("sso_sessions.user_id foreign key = %q, want %q", fk, want)
	}
}

// queryStrings returns every row of a query as its text columns.
func queryStrings(t *testing.T, db *sql.DB, query string, args ...any) [][]string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = v.String
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Covers: FR-35 (part)
// A second verified user with the email of the first violates a once-only key.
// Postgres runs the function twice (one run again) and the second violation is
// the conflict: ErrConflict, not ErrUnavailable.
func TestPostgresRepeatedUniqueViolationRunsTwice(t *testing.T) {
	ctx := t.Context()
	s := testutil.NewPostgresStore(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := s.Write(ctx, func(tx store.Tx) error {
		_, err := tx.Realms().Ensure(ctx, "r1", "realm-1", now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	user := func(id string) store.User {
		return store.User{ID: store.UserID(id), RealmID: "realm-1", Email: "bo@example.com",
			EmailKey: "bo@example.com", EmailVerified: true, CreatedAt: now, UpdatedAt: now}
	}
	if err := s.Write(ctx, func(tx store.Tx) error { return tx.Users().Create(ctx, user("uq-1")) }); err != nil {
		t.Fatal(err)
	}
	runs := 0
	err := s.Write(ctx, func(tx store.Tx) error {
		runs++
		return tx.Users().Create(ctx, user("uq-2"))
	})
	if !errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrUnavailable) || runs != 2 {
		t.Fatalf("Write = %v after %d runs, want ErrConflict after 2 runs", err, runs)
	}
}
