package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/yyudhistira/featherauth/internal/config"
)

// Errors of db copy, to be tested with errors.Is.
var (
	// ErrTargetNotEmpty means a table of the target holds a row. Nothing is written.
	ErrTargetNotEmpty = errors.New("the target database is not empty")
	// ErrSourceVersion means the source has no schema version or another one than
	// this binary expects. Nothing is written.
	ErrSourceVersion = errors.New("the source database has another schema version")
	// ErrCopyMismatch means a table of the target differs from the source after
	// the copy. The target is rolled back.
	ErrCopyMismatch = errors.New("a table of the copy differs from the source; the target is unchanged")
)

// TableCopy is the outcome of one table of a copy: its rows in the source, the
// rows read back from the target, and whether their counts and checksums agree.
type TableCopy struct {
	Table      string
	Rows       int64
	TargetRows int64
	Match      bool
}

// CopySQLiteToPostgres copies every table of the SQLite database from to the
// Postgres database to, as db copy does; toSecrets are the secrets of the
// database.yaml of to. It checks the source first (its schema version and tables),
// then the target (no rows), migrates the target, and writes every row in one write
// transaction, reading the source in one read transaction. Before it commits it
// reads each table back and compares the row count and checksum with the source's;
// a difference rolls the target back and returns ErrCopyMismatch. It returns one
// entry for each table in copy order, also when a check fails.
func CopySQLiteToPostgres(ctx context.Context, from, to config.DatabaseFile, toSecrets config.DatabaseSecrets) ([]TableCopy, error) {
	if from.Driver != "sqlite" || to.Driver != "postgres" {
		return nil, fmt.Errorf("db copy copies a sqlite database to a postgres database, not from %s to %s", from.Driver, to.Driver)
	}
	names, version, err := migrationSchema(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	src, err := openSQLiteSource(from.SQLite)
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()
	srcTx, err := src.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = srcTx.Rollback() }()
	tables, err := sourceTables(ctx, srcTx, names, version)
	if err != nil {
		return nil, err
	}

	dst, err := openPostgresDB(to.Postgres, toSecrets)
	if err != nil {
		return nil, err
	}
	if err := refuseRowsBeforeMigrating(ctx, dst, names); err != nil {
		_ = dst.Close()
		return nil, err
	}
	st, err := NewPostgres(ctx, dst)
	if err != nil {
		return nil, err
	}
	defer func() { _ = st.Close() }()

	var out []TableCopy
	err = st.Write(ctx, func(tx Tx) error {
		out = nil // a run again starts from nothing
		return copyTables(ctx, tx.(*sqlTx), srcTx, tables, &out)
	})
	return out, err
}

// copyTables writes the rows of every table into the target transaction tx from
// the source transaction src, then reads each table back and compares it with the
// source. The results go to out, which holds every table also when the check fails.
func copyTables(ctx context.Context, tx *sqlTx, src *sql.Tx, tables []sourceTable, out *[]TableCopy) error {
	q := tx.q
	names := make([]string, len(tables))
	for i, t := range tables {
		names[i] = t.name
	}
	if err := refuseRows(ctx, q, names); err != nil {
		return err
	}
	sums := make([]*copyDigest, len(tables))
	for i, t := range tables {
		types, err := columnTypes(ctx, q, t)
		if err != nil {
			return err
		}
		if sums[i], err = insertRows(ctx, q, src, t, types); err != nil {
			return err
		}
	}

	results := make([]TableCopy, 0, len(tables))
	mismatch := false
	for i, t := range tables {
		back := newCopyDigest()
		backTypes, err := columnTypes(ctx, q, t)
		if err != nil {
			return err
		}
		if err := eachRow(ctx, q, t, t.selectSQL(keyCollation(q), backTypes), back.add); err != nil {
			return err
		}
		match := back.rows == sums[i].rows && back.sum() == sums[i].sum()
		results = append(results, TableCopy{Table: t.name, Rows: sums[i].rows, TargetRows: back.rows, Match: match})
		mismatch = mismatch || !match
	}
	*out = results
	if mismatch {
		return ErrCopyMismatch
	}
	return nil
}

// sourceTable is one table of a copy: its name, its columns in declaration order
// and its primary key, as indexes into the columns in key order.
type sourceTable struct {
	name string
	cols []string
	key  []int
}

// selectSQL reads every column of the table in key order: the rows sorted by the
// bytes of their key's canonical text. collate is the clause that makes a text key
// compare by bytes (see keyCollation). types maps each column to its type name; an
// integer key is ordered as its decimal text (CAST AS TEXT, with the same clause),
// because the checksum orders the rows by that text, and Postgres refuses a
// collation on a number.
func (t sourceTable) selectSQL(collate string, types map[string]string) string {
	order := make([]string, len(t.key))
	for i, k := range t.key {
		col := t.cols[k]
		switch {
		case isTextType(types[col]):
			order[i] = col + collate
		case isIntType(types[col]):
			order[i] = "CAST(" + col + " AS TEXT)" + collate
		default:
			order[i] = col + collate
		}
	}
	return "SELECT " + strings.Join(t.cols, ", ") + " FROM " + t.name + " ORDER BY " + strings.Join(order, ", ")
}

// isIntType reports whether a column of this database type name holds an integer
// (SQLite's INTEGER, Postgres' bigint, integer and smallint).
func isIntType(typ string) bool {
	switch typ {
	case "INTEGER", "INT2", "INT4", "INT8":
		return true
	}
	return false
}

// isTextType reports whether a column of this database type name holds text, the
// types that a collation applies to.
func isTextType(typ string) bool {
	switch typ {
	case "TEXT", "VARCHAR", "BPCHAR", "CHAR":
		return true
	}
	return false
}

// keyCollation is the clause that makes an ORDER BY on the target compare text by
// bytes. Postgres sorts text by its locale unless it is told the C collation;
// SQLite compares text by bytes already.
func keyCollation(q dbtx) string {
	if _, ok := q.(pgRebind); ok {
		return ` COLLATE "C"`
	}
	return ""
}

// sourceTables checks the source: its migration table holds version as its
// highest applied migration, and its tables are exactly names. It returns the
// columns and the primary key of each table of names. A source that has no
// migration table is another schema version too.
func sourceTables(ctx context.Context, tx *sql.Tx, names []string, version int64) ([]sourceTable, error) {
	var migrations int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'goose_db_version'`).Scan(&migrations); err != nil {
		return nil, err
	}
	if migrations == 0 {
		return nil, fmt.Errorf("%w: it has no migration table", ErrSourceVersion)
	}
	var got int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied = 1`).Scan(&got); err != nil {
		return nil, err
	}
	if got != version {
		return nil, fmt.Errorf("%w: version %d, this binary expects %d", ErrSourceVersion, got, version)
	}

	present, err := sqliteTableNames(ctx, tx)
	if err != nil {
		return nil, err
	}
	want := slices.Clone(names)
	slices.Sort(present)
	slices.Sort(want)
	if !slices.Equal(present, want) {
		return nil, fmt.Errorf("the source has tables %v, the schema has %v", present, want)
	}

	out := make([]sourceTable, 0, len(names))
	for _, name := range names {
		t, err := sqliteTable(ctx, tx, name)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// sqliteTableNames returns the names of the tables of the SQLite database, without
// the migration table and SQLite's own tables.
func sqliteTableNames(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if name == "goose_db_version" || strings.HasPrefix(name, "sqlite_") {
			continue
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// sqliteTable reads the columns and the primary key of one table of the source.
func sqliteTable(ctx context.Context, tx *sql.Tx, name string) (sourceTable, error) {
	// PRAGMA takes no placeholder; the name comes from the migrations.
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info("+name+")")
	if err != nil {
		return sourceTable{}, err
	}
	defer func() { _ = rows.Close() }()
	t := sourceTable{name: name}
	type keyPart struct{ pos, col int }
	var parts []keyPart
	for rows.Next() {
		var cid, notnull, pk int
		var colName, colType string
		var dflt any
		if err := rows.Scan(&cid, &colName, &colType, &notnull, &dflt, &pk); err != nil {
			return sourceTable{}, err
		}
		if pk > 0 {
			parts = append(parts, keyPart{pk, len(t.cols)})
		}
		t.cols = append(t.cols, colName)
	}
	if err := rows.Err(); err != nil {
		return sourceTable{}, err
	}
	if len(t.cols) == 0 || len(parts) == 0 {
		return sourceTable{}, fmt.Errorf("table %s has no columns or no primary key", name)
	}
	slices.SortFunc(parts, func(a, b keyPart) int { return a.pos - b.pos })
	for _, p := range parts {
		t.key = append(t.key, p.col)
	}
	return t, nil
}

// columnTypes returns the database type name of each column of the target table,
// as the driver reports it: BOOL for a Postgres boolean. A query without rows
// still describes its columns.
func columnTypes(ctx context.Context, q dbtx, t sourceTable) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, "SELECT "+strings.Join(t.cols, ", ")+" FROM "+t.name+" LIMIT 0")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	cts, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(cts))
	for _, ct := range cts {
		out[ct.Name()] = ct.DatabaseTypeName()
	}
	return out, rows.Err()
}

// insertRows copies the rows of one table from the source into the target and
// returns the checksum of the source rows.
func insertRows(ctx context.Context, q dbtx, src *sql.Tx, t sourceTable, types map[string]string) (*copyDigest, error) {
	d := newCopyDigest()
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(t.cols)), ", ")
	insert := "INSERT INTO " + t.name + " (" + strings.Join(t.cols, ", ") + ") VALUES (" + marks + ")"
	srcTypes, err := columnTypes(ctx, src, t)
	if err != nil {
		return nil, err
	}
	err = eachRow(ctx, src, t, t.selectSQL("", srcTypes), func(vals []any) error {
		args := make([]any, len(vals))
		for i, v := range vals {
			a, err := targetValue(v, types[t.cols[i]])
			if err != nil {
				return fmt.Errorf("table %s, column %s: %w", t.name, t.cols[i], err)
			}
			args[i] = a
		}
		if _, err := q.ExecContext(ctx, insert, args...); err != nil {
			return fmt.Errorf("copy table %s: %w", t.name, err)
		}
		return d.add(vals)
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

// targetValue returns the value to write for v in a column of the target type
// typ, as columnTypes names it: SQLite stores a boolean as 0 or 1, Postgres has a
// BOOL type that takes true or false.
func targetValue(v any, typ string) (any, error) {
	switch x := v.(type) {
	case nil, string:
		return v, nil
	case int64:
		if typ == "BOOL" {
			switch x {
			case 0:
				return false, nil
			case 1:
				return true, nil
			}
			return nil, fmt.Errorf("the value %d is not a boolean", x)
		}
		return x, nil
	default:
		return nil, fmt.Errorf("a value of type %T cannot be copied", v)
	}
}

// eachRow runs query, which reads the columns of t in key order, and calls fn with
// the values of each row. The keys must come in strictly increasing byte order, as
// the checksum needs; a row out of order fails the copy.
func eachRow(ctx context.Context, q dbtx, t sourceTable, query string, fn func([]any) error) error {
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var prev []string
	for rows.Next() {
		vals := make([]any, len(t.cols))
		ptrs := make([]any, len(vals))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		key := make([]string, len(t.key))
		for j, k := range t.key {
			text, null, err := canonicalText(vals[k])
			if err != nil || null {
				return fmt.Errorf("table %s: a key column is not text or an integer", t.name)
			}
			key[j] = string(text)
		}
		if prev != nil && compareKeys(prev, key) >= 0 {
			return fmt.Errorf("table %s: the rows are not in key order", t.name)
		}
		prev = key
		if err := fn(vals); err != nil {
			return err
		}
	}
	return rows.Err()
}

// compareKeys compares two primary keys column by column, by bytes.
func compareKeys(a, b []string) int {
	for i := range a {
		if c := strings.Compare(a[i], b[i]); c != 0 {
			return c
		}
	}
	return 0
}

// refuseRowsBeforeMigrating checks the target before the migrations run on it, so
// that a target that holds rows is not changed at all. It reads in a transaction of
// its own on db and leaves db open.
func refuseRowsBeforeMigrating(ctx context.Context, db *sql.DB, names []string) error {
	tx, err := db.BeginTx(ctx, pgReadOpts)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	return refuseRowsOfExisting(ctx, pgRebind{tx: tx}, names)
}

// refuseRowsOfExisting returns ErrTargetNotEmpty for the first table of names that
// exists and holds a row. A table that does not exist yet holds none.
func refuseRowsOfExisting(ctx context.Context, q dbtx, names []string) error {
	for _, name := range names {
		exists, err := tableExists(ctx, q, name)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if err := refuseRows(ctx, q, []string{name}); err != nil {
			return err
		}
	}
	return nil
}

// tableExists reports whether the database of q has the table. The catalog differs
// by driver: information_schema on Postgres, sqlite_master on SQLite.
func tableExists(ctx context.Context, q dbtx, name string) (bool, error) {
	query := `SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)`
	if _, ok := q.(pgRebind); ok {
		query = `SELECT EXISTS (SELECT 1 FROM information_schema.tables
			WHERE table_schema = current_schema() AND table_name = ?)`
	}
	var exists bool
	err := q.QueryRowContext(ctx, query, name).Scan(&exists)
	return exists, err
}

// refuseRows returns ErrTargetNotEmpty for the first table of names that holds a
// row. Its tables must exist, as they do once the migrations have run.
func refuseRows(ctx context.Context, q dbtx, names []string) error {
	for _, name := range names {
		var has bool
		if err := q.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM "+name+")").Scan(&has); err != nil {
			return err
		}
		if has {
			return fmt.Errorf("%w: table %s has rows", ErrTargetNotEmpty, name)
		}
	}
	return nil
}

// openSQLiteSource opens the SQLite database of cfg for reading. It does not
// migrate the database and changes nothing in it: the connection is read-only.
func openSQLiteSource(cfg config.SQLiteConfig) (*sql.DB, error) {
	if _, err := os.Stat(cfg.Path); err != nil {
		return nil, fmt.Errorf("cannot read the SQLite database: %w", err)
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout("+strconv.FormatInt(cfg.BusyTimeout.Std().Milliseconds(), 10)+")")
	q.Add("_pragma", "query_only(1)")
	u := url.URL{Scheme: "file", Opaque: url.PathEscape(cfg.Path), RawQuery: q.Encode()}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// createTable matches the CREATE TABLE statements of the migrations.
var createTable = regexp.MustCompile(`(?m)^CREATE TABLE (\w+) \(`)

// migrationSchema reads the SQLite migrations in dir of fsys and returns the tables
// they create, in the order they are created (so a table is copied after the tables
// it refers to), and the version of the newest migration: the number that starts
// its file name. Only the Up part of each file counts.
func migrationSchema(fsys fs.FS, dir string) (tables []string, version int64, err error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, 0, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		prefix, _, _ := strings.Cut(e.Name(), "_")
		v, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("migration %s has no version number", e.Name())
		}
		version = max(version, v)
		b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, 0, err
		}
		text := string(b)
		if i := strings.Index(text, "-- +goose Down"); i >= 0 {
			text = text[:i]
		}
		for _, m := range createTable.FindAllStringSubmatch(text, -1) {
			if !slices.Contains(tables, m[1]) {
				tables = append(tables, m[1])
			}
		}
	}
	if len(tables) == 0 {
		return nil, 0, errors.New("the migrations create no table")
	}
	return tables, version, nil
}

// copyDigest is the checksum of the rows of one table. Each row is its values in
// column order, and each value is one byte (0 for a null, 1 for a value), the
// length of its canonical text as 8 bytes big-endian, and the text.
type copyDigest struct {
	h    hash.Hash
	rows int64
}

func newCopyDigest() *copyDigest { return &copyDigest{h: sha256.New()} }

// add folds one row into the checksum.
func (d *copyDigest) add(vals []any) error {
	var n [8]byte
	for _, v := range vals {
		text, null, err := canonicalText(v)
		if err != nil {
			return err
		}
		marker := byte(1)
		if null {
			marker = 0
		}
		_, _ = d.h.Write([]byte{marker})
		binary.BigEndian.PutUint64(n[:], uint64(len(text)))
		_, _ = d.h.Write(n[:])
		_, _ = d.h.Write(text)
	}
	d.rows++
	return nil
}

// sum returns the checksum of the rows added so far.
func (d *copyDigest) sum() [32]byte {
	var out [32]byte
	copy(out[:], d.h.Sum(nil))
	return out
}

// canonicalText returns the text of a value that the checksum covers: a text as
// its bytes, a number in decimal, a boolean as 0 or 1. A null has no text.
func canonicalText(v any) (text []byte, null bool, err error) {
	switch x := v.(type) {
	case nil:
		return nil, true, nil
	case string:
		return []byte(x), false, nil
	case int64:
		return strconv.AppendInt(nil, x, 10), false, nil
	case bool:
		if x {
			return []byte("1"), false, nil
		}
		return []byte("0"), false, nil
	default:
		return nil, false, fmt.Errorf("a value of type %T has no canonical text", v)
	}
}
