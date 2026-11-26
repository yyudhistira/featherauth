//go:build postgres

package token_test

import (
	"testing"

	"github.com/yyudhistira/featherauth/internal/store/storetest"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// This test closes the row "Postgres concurrency" on Postgres. It runs the token
// service's cases (20 exchanges of one code, 20 refreshes in grace, the deadlock
// runs, the refused first runs) and the store's concurrency cases (the verified
// email race, the deadlock runs, the unique violations). Together they assert
// every pass condition of the row. TestPostgresStoreContract has the store part
// only, as (part).
// Covers: FR-35 (part)
// Acceptance: Postgres concurrency
func TestDriverCasesPostgres(t *testing.T) {
	runDriverCases(t, testutil.NewPostgresStore)
	storetest.RunConcurrency(t, testutil.NewPostgresStore)
}
