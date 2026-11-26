//go:build postgres

package main

import (
	"fmt"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil"
)

// postgresDrivers is the Postgres driver of the admin tests: a database of its
// own on the server named by FEATHERAUTH_TEST_POSTGRES. The password is written
// to secrets/postgres_password (mode 0600, as strict_permissions requires), and
// database.yaml names it.
func postgresDrivers() []dbDriver {
	return []dbDriver{{name: "postgres", provision: func(t *testing.T, dir, backups string) string {
		t.Helper()
		srv := testutil.NewPostgresServer(t)
		pg := srv.NewDatabase(t)
		writeConfig(t, dir, "secrets/postgres_password", srv.Password+"\n")
		writeConfig(t, dir, "database.yaml", fmt.Sprintf("driver: postgres\npostgres:\n  host: %s\n  port: %d\n  database: %s\n  user: %s\n  password_file: secrets/postgres_password\n  sslmode: disable\n%s",
			pg.Host, pg.Port, pg.Database, pg.User, backupBlock(backups)))
		return ""
	}}}
}
