package store

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"

	"github.com/yyudhistira/featherauth/internal/config"
)

// ExecForTest runs one statement in a write transaction of s.
func ExecForTest(ctx context.Context, s Store, query string, args ...any) error {
	return s.Write(ctx, func(tx Tx) error {
		_, err := tx.(*sqlTx).q.ExecContext(ctx, query, args...)
		return err
	})
}

// RawTx returns the *sql.Tx behind a transaction.
func RawTx(tx Tx) *sql.Tx { return tx.(*sqlTx).tx }

// ReadPoolSize returns the read connection limit of a sqlite store.
func ReadPoolSize(s Store) int { return s.(*sqliteStore).read.Stats().MaxOpenConnections }

// PostgresConnConfig is the connection configuration of a Postgres store.
func PostgresConnConfig(cfg config.PostgresConfig, s config.DatabaseSecrets) (*pgx.ConnConfig, error) {
	return postgresConnConfig(cfg, s)
}

// SetQueryOnlyForTest makes the write connection of a sqlite store refuse every
// write (on) or accept them again (off). A VACUUM INTO on it fails with "attempt
// to write a readonly database", as a snapshot writer does on a full disk.
func SetQueryOnlyForTest(ctx context.Context, s Store, on bool) error {
	value := "OFF"
	if on {
		value = "ON"
	}
	_, err := s.(*sqliteStore).write.ExecContext(ctx, "PRAGMA query_only = "+value)
	return err
}
