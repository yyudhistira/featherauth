// Package testutil holds shared helpers for tests. Only tests and other test
// support packages may import it.
package testutil

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
)

// DatabaseConfig returns the default SQLite database configuration for a file.
func DatabaseConfig(path string) config.DatabaseFile {
	return config.DatabaseFile{
		Driver: "sqlite",
		SQLite: config.SQLiteConfig{
			Path:            path,
			BusyTimeout:     config.Duration(5 * time.Second),
			JournalMode:     "wal",
			ReadConnections: 4,
		},
	}
}

// NewStore opens a migrated SQLite store on a temporary file and closes it when
// the test ends.
func NewStore(t testing.TB) store.Store {
	t.Helper()
	s, _ := NewStoreFile(t)
	return s
}

// NewStoreFile is NewStore that also returns the path of the database file,
// for tests that open a second store on it as the CLI does.
func NewStoreFile(t testing.TB) (store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "featherauth.db")
	s, err := store.Open(context.Background(), DatabaseConfig(path), config.DatabaseSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}
