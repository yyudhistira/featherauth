package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"strconv"

	"github.com/pressly/goose/v3"
	"modernc.org/sqlite"

	"github.com/yyudhistira/featherauth/internal/config"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

var (
	_ Store = (*sqliteStore)(nil)
	_ Tx    = (*sqlTx)(nil)
)

var journalModeRE = regexp.MustCompile(`^[a-z]+$`)

type sqliteStore struct {
	write *sql.DB // one connection; all writes
	read  *sql.DB // sqlite.read_connections connections
}

// openSQLite opens the SQLite database named by cfg and applies the migrations.
// Open chooses it by the driver of cfg.
func openSQLite(ctx context.Context, cfg config.DatabaseFile) (Store, error) {
	if !journalModeRE.MatchString(cfg.SQLite.JournalMode) {
		return nil, fmt.Errorf("invalid sqlite.journal_mode %q", cfg.SQLite.JournalMode)
	}
	if cfg.SQLite.ReadConnections < 1 {
		return nil, fmt.Errorf("sqlite.read_connections must be 1 or more, got %d", cfg.SQLite.ReadConnections)
	}

	write, err := sql.Open("sqlite", dsn(cfg, true))
	if err != nil {
		return nil, err
	}
	write.SetMaxOpenConns(1)
	write.SetMaxIdleConns(1)
	if err := migrate(ctx, write); err != nil {
		_ = write.Close()
		return nil, fmt.Errorf("migrate database: %w", mapErr(err))
	}
	read, err := sql.Open("sqlite", dsn(cfg, false))
	if err != nil {
		_ = write.Close()
		return nil, err
	}
	read.SetMaxOpenConns(cfg.SQLite.ReadConnections)
	read.SetMaxIdleConns(cfg.SQLite.ReadConnections)
	s := &sqliteStore{write: write, read: read}
	if err := s.Ping(ctx); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func dsn(cfg config.DatabaseFile, writer bool) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout("+strconv.FormatInt(cfg.SQLite.BusyTimeout.Std().Milliseconds(), 10)+")")
	q.Add("_pragma", "journal_mode("+cfg.SQLite.JournalMode+")")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(1)")
	if writer {
		q.Set("_txlock", "immediate")
	} else {
		q.Add("_pragma", "query_only(1)")
	}
	u := url.URL{Scheme: "file", Opaque: url.PathEscape(cfg.SQLite.Path), RawQuery: q.Encode()}
	return u.String()
}

func migrate(ctx context.Context, db *sql.DB) error {
	sub, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		return err
	}
	p, err := goose.NewProvider(goose.DialectSQLite3, db, sub)
	if err != nil {
		return err
	}
	_, err = p.Up(ctx)
	return err
}

// mapErr turns a busy or locked database into ErrUnavailable.
func mapErr(err error) error {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case 5, 6: // SQLITE_BUSY, SQLITE_LOCKED
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	return err
}

// sqlTx gives the repositories of one transaction, on either driver. The SQL
// is the same text for both; q is what the repositories run it on: the
// transaction itself on SQLite, and a wrapper that numbers the placeholders on
// Postgres.
type sqlTx struct {
	tx *sql.Tx
	q  dbtx
}

// sqliteTxOf wraps a SQLite transaction; its SQL uses ? placeholders as is.
func sqliteTxOf(tx *sql.Tx) Tx { return &sqlTx{tx: tx, q: tx} }

// The repositories are in repos.go, authrepos.go, refreshrepo.go, ssorepo.go and auditrepo.go.
func (t *sqlTx) Realms() Realms                           { return realmRepo{t.q} }
func (t *sqlTx) Users() Users                             { return userRepo{t.q} }
func (t *sqlTx) Identities() Identities                   { return identityRepo{t.q} }
func (t *sqlTx) AuthRequests() AuthRequests               { return authRequestRepo{t.q} }
func (t *sqlTx) AuthCodes() AuthCodes                     { return authCodeRepo{t.q} }
func (t *sqlTx) Handoffs() Handoffs                       { return handoffRepo{t.q} }
func (t *sqlTx) ProviderEvents() ProviderEvents           { return providerEventRepo{t.q} }
func (t *sqlTx) RefreshTokens() RefreshTokens             { return refreshRepo{t.q} }
func (t *sqlTx) LogoutNotifications() LogoutNotifications { return logoutRepo{t.q} }
func (t *sqlTx) DPoPProofs() DPoPProofs                   { return dpopRepo{t.q} }
func (t *sqlTx) RateLimits() RateLimits                   { return rateLimitRepo{t.q} }
func (t *sqlTx) SSOSessions() SSOSessions                 { return ssoRepo{t.q} }
func (t *sqlTx) Audit() Audit                             { return auditRepo{t.q} }

// run runs fn in one transaction of db, with the repositories of wrap and the
// transaction options opts (nil for the driver's defaults).
func run(ctx context.Context, db *sql.DB, opts *sql.TxOptions, wrap func(*sql.Tx) Tx, fn func(Tx) error) (err error) {
	tx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return mapErr(err)
	}
	defer func() {
		if r := recover(); r != nil {
			_ = tx.Rollback()
			panic(r)
		}
	}()
	if err := fn(wrap(tx)); err != nil {
		_ = tx.Rollback()
		return mapErr(err)
	}
	return mapErr(tx.Commit())
}

func (s *sqliteStore) Read(ctx context.Context, fn func(Tx) error) error {
	return run(ctx, s.read, nil, sqliteTxOf, fn)
}

func (s *sqliteStore) Write(ctx context.Context, fn func(Tx) error) error {
	return retryWrite(ctx, func(ctx context.Context) error {
		return run(ctx, s.write, nil, sqliteTxOf, fn)
	})
}

// Ping checks that the database file is reachable. It uses the read pool
// only: the write connection is a queue under load, and a readiness check
// that waited in it would fail while the service is serving.
func (s *sqliteStore) Ping(ctx context.Context) error {
	return mapErr(s.read.PingContext(ctx))
}

// Backup writes a snapshot to path, which must not exist. A snapshot that fails
// leaves no file behind (SQLite creates the file before it writes it): a partial
// file would count as one of the snapshots to keep and displace a good one. A
// file that existed before is never touched.
func (s *sqliteStore) Backup(ctx context.Context, path string) error {
	_, statErr := os.Lstat(path)
	existed := statErr == nil
	_, err := s.write.ExecContext(ctx, "VACUUM INTO ?", path)
	if err != nil && !existed {
		_ = os.Remove(path)
	}
	return mapErr(err)
}

func (s *sqliteStore) Close() error {
	return errors.Join(s.read.Close(), s.write.Close())
}
