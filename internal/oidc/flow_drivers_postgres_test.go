//go:build postgres

package oidc_test

import "github.com/yyudhistira/featherauth/internal/testutil/server"

// postgresFlowDrivers is the Postgres driver of the flows: a database of its own
// on the server named by FEATHERAUTH_TEST_POSTGRES (make postgres).
func postgresFlowDrivers() []flowDriver {
	return []flowDriver{{name: "postgres", opts: []server.Option{server.WithPostgres()}}}
}
