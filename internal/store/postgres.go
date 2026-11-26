package store

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/postgres/*.sql
var postgresMigrationFiles embed.FS

var _ Store = (*postgresStore)(nil)

// postgresStore is the Store of a Postgres database. Reads and writes share one
// pool, and its transactions follow the rules of the Postgres store (see Read and
// Write).
type postgresStore struct {
	db *sql.DB
	// ping is the connection of the readiness ping, apart from db: a ping through
	// db would wait for a connection of the pool behind the writes. Nil means
	// the ping goes through db (NewPostgres, the copy and the test database).
	ping *sql.DB
}

// NewPostgres applies the migrations to the Postgres database behind db and
// returns the store that uses it. The store takes db over: NewPostgres closes
// db when it fails, and Close closes it.
func NewPostgres(ctx context.Context, db *sql.DB) (Store, error) {
	return newPostgres(ctx, db, nil)
}

// newPostgres is NewPostgres with the database of the readiness ping (nil for
// db itself). The store takes ping over as well.
func newPostgres(ctx context.Context, db, ping *sql.DB) (Store, error) {
	fsys, err := postgresMigrations()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	// The session lock is a Postgres advisory lock: two instances that start at
	// once apply the migrations one after the other, the second finding them
	// applied (FR-54).
	var p *goose.Provider
	locker, err := lock.NewPostgresSessionLocker()
	if err == nil {
		p, err = goose.NewProvider(goose.DialectPostgres, db, fsys, goose.WithSessionLocker(locker))
	}
	if err == nil {
		_, err = p.Up(ctx)
	}
	if err != nil {
		_ = db.Close()
		if ping != nil {
			_ = ping.Close()
		}
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	return &postgresStore{db: db, ping: ping}, nil
}

// postgresMigrations returns the migrations of Postgres: the shared files, each
// replaced by the file of the same name under migrations/postgres when there is
// one. A Postgres file exists only where the SQL differs.
func postgresMigrations() (fs.FS, error) {
	shared, err := readSQL(migrationFiles, "migrations")
	if err != nil {
		return nil, err
	}
	own, err := readSQL(postgresMigrationFiles, "migrations/postgres")
	if err != nil {
		return nil, err
	}
	return overlayMigrations(shared, own), nil
}

// readSQL returns the files of dir in fsys by name, skipping subdirectories.
func readSQL(fsys fs.FS, dir string) (map[string][]byte, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, err
		}
		out[e.Name()] = b
	}
	return out, nil
}

// overlayMigrations serves the shared files, each replaced by the file of the
// same name in own when there is one. A name only in own is served too.
func overlayMigrations(shared, own map[string][]byte) mapFS {
	out := mapFS{}
	for name, b := range shared {
		out[name] = b
	}
	for name, b := range own {
		out[name] = b
	}
	return out
}

// mapFS is a read-only, in-memory fs.FS of files in one directory, the root.
// Goose reads the migrations through it: it lists the root and reads files.
type mapFS map[string][]byte

var (
	_ fs.ReadDirFS  = mapFS(nil)
	_ fs.ReadFileFS = mapFS(nil)
)

func (m mapFS) Open(name string) (fs.File, error) {
	b, ok := m[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &mapFile{info: mapInfo{name: name, size: int64(len(b))}, r: bytes.NewReader(b)}, nil
}

func (m mapFS) ReadFile(name string) ([]byte, error) {
	b, ok := m[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return slices.Clone(b), nil
}

// ReadDir lists the root of the map, sorted by name.
func (m mapFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	var names []string
	for n := range m {
		names = append(names, n)
	}
	slices.Sort(names)
	out := make([]fs.DirEntry, 0, len(names))
	for _, n := range names {
		out = append(out, fs.FileInfoToDirEntry(mapInfo{name: n, size: int64(len(m[n]))}))
	}
	return out, nil
}

// mapFile is an open mapFS file.
type mapFile struct {
	info mapInfo
	r    *bytes.Reader
}

func (f *mapFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *mapFile) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *mapFile) Close() error               { return nil }

// mapInfo describes a mapFS file: a regular file, read-only.
type mapInfo struct {
	name string
	size int64
}

func (i mapInfo) Name() string       { return i.name }
func (i mapInfo) Size() int64        { return i.size }
func (i mapInfo) Mode() fs.FileMode  { return 0o444 }
func (i mapInfo) ModTime() time.Time { return time.Time{} }
func (i mapInfo) IsDir() bool        { return false }
func (i mapInfo) Sys() any           { return nil }

// rebind numbers the ? placeholders of a query as $1, $2, ... for Postgres. A
// question mark inside a single-quoted literal is left alone.
func rebind(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	quoted := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case c == '\'':
			quoted = !quoted
		case c == '?' && !quoted:
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// pgRebind runs the shared SQL of the repositories on a Postgres transaction.
// lock is set for a write transaction: its decisive reads take row locks.
type pgRebind struct {
	tx   *sql.Tx
	lock bool
}

func (p pgRebind) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return p.tx.ExecContext(ctx, rebind(query), args...)
}

func (p pgRebind) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return p.tx.QueryContext(ctx, rebind(query), args...)
}

func (p pgRebind) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return p.tx.QueryRowContext(ctx, rebind(query), args...)
}

// rowLock is the clause that locks the rows a SELECT reads in a write
// transaction of Postgres. The lock holds until that transaction ends, so a
// second transaction on the same row waits and then reads what the first one
// wrote. Read transactions cannot lock, and SQLite's one write connection already
// runs the writes one at a time, so neither gets the clause.
func rowLock(q dbtx) string {
	if p, ok := q.(pgRebind); ok && p.lock {
		return " FOR UPDATE"
	}
	return ""
}

// postgresWriteTxOf wraps a write transaction of Postgres for the repositories.
func postgresWriteTxOf(tx *sql.Tx) Tx { return &sqlTx{tx: tx, q: pgRebind{tx: tx, lock: true}} }

// postgresReadTxOf wraps a read transaction of Postgres for the repositories.
func postgresReadTxOf(tx *sql.Tx) Tx { return &sqlTx{tx: tx, q: pgRebind{tx: tx}} }

// The transaction modes of Postgres. A write runs at READ COMMITTED, so a
// transaction that waits for a row lock reads the row's latest version. A read
// runs read-only at REPEATABLE READ, so one read sees one state, as on SQLite.
var (
	pgReadOpts  = &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	pgWriteOpts = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
)

func (s *postgresStore) Read(ctx context.Context, fn func(Tx) error) error {
	return run(ctx, s.db, pgReadOpts, postgresReadTxOf, fn)
}

func (s *postgresStore) Write(ctx context.Context, fn func(Tx) error) error {
	return retryWrite(ctx, func(ctx context.Context) error {
		return run(ctx, s.db, pgWriteOpts, postgresWriteTxOf, fn)
	})
}

// Ping checks that the database answers on a connection of its own, which the
// queue of the pool does not hold.
func (s *postgresStore) Ping(ctx context.Context) error {
	if s.ping != nil {
		return s.ping.PingContext(ctx)
	}
	return s.db.PingContext(ctx)
}

// Backup is not built in for Postgres: the snapshot of a Postgres database is
// taken with pg_dump, as the design says.
func (s *postgresStore) Backup(context.Context, string) error {
	return errors.New("store: the built-in backup is for sqlite only; back up postgres with pg_dump")
}

func (s *postgresStore) Close() error {
	if s.ping != nil {
		_ = s.ping.Close()
	}
	return s.db.Close()
}
