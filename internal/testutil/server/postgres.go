//go:build postgres

package server

import (
	"testing"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// WithPostgres runs the service on a Postgres database of its own, on the
// server named by FEATHERAUTH_TEST_POSTGRES (make postgres). It has no database
// file, so Env.DatabasePath is empty.
func WithPostgres() Option {
	return WithStore(func(t testing.TB) (store.Store, string) {
		return testutil.NewPostgresStore(t), ""
	})
}
