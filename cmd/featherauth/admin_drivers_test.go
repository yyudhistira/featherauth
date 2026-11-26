package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/store"
)

// dbDriver is a database the CLI tests run on: the sqlite driver always, and the
// postgres driver under the postgres tag (make postgres). A test that takes a
// driver runs once for each, so the commands are proved on both.
type dbDriver struct {
	name string
	// provision writes database.yaml into the configuration directory dir for a
	// new, empty database, with snapshots in backups (a driver that takes none
	// ignores it), and the secret files it names. It returns the SQLite file, or
	// "" for a driver without one.
	provision func(t *testing.T, dir, backups string) string
	// snapshots is true when the driver's backup is a SQLite snapshot
	// (featherauth backup); the others refuse it.
	snapshots bool
}

// sqliteDriver is the SQLite database of a new file in dir's parent directory.
var sqliteDriver = dbDriver{name: "sqlite", snapshots: true, provision: func(t *testing.T, dir, backups string) string {
	t.Helper()
	db := filepath.Join(filepath.Dir(dir), "featherauth.db")
	writeConfig(t, dir, "database.yaml", "driver: sqlite\nsqlite:\n  path: "+db+"\n"+backupBlock(backups))
	return db
}}

// backupBlock is the backup block of database.yaml for a directory ("" for none).
func backupBlock(dir string) string {
	if dir == "" {
		return ""
	}
	return "backup:\n  directory: " + dir + "\n  keep: 2\n"
}

// dbDrivers returns the drivers the admin tests run on.
func dbDrivers() []dbDriver {
	return append([]dbDriver{sqliteDriver}, postgresDrivers()...)
}

// forEachDB runs fn once for each driver, as a subtest named after it.
func forEachDB(t *testing.T, fn func(t *testing.T, d dbDriver)) {
	t.Helper()
	for _, d := range dbDrivers() {
		t.Run(d.name, func(t *testing.T) { fn(t, d) })
	}
}

// openConfiguredDatabase opens the database that database.yaml in dir names,
// with the secrets of that file, as the CLI and the service do. It closes the
// store when the test ends.
func openConfiguredDatabase(t *testing.T, dir string) store.Store {
	t.Helper()
	a := &app{getenv: func(k string) string {
		if k == envConfigDir {
			return dir
		}
		return ""
	}, clock: clock.NewFake(time.Unix(0, 0))}
	st, _, err := a.openDatabase(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
