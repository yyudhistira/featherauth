package oidc_test

import (
	"slices"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// flowDriver is a database the full flows run on. The sqlite driver always runs;
// the postgres driver is added under the postgres tag (make postgres), so the
// same flows prove the service on both drivers.
type flowDriver struct {
	name string
	opts []server.Option
}

// flowDrivers returns the drivers of the flows: sqlite, and postgres under the
// postgres tag.
func flowDrivers() []flowDriver {
	return append([]flowDriver{{name: "sqlite"}}, postgresFlowDrivers()...)
}

// forEachFlowDriver runs fn once for each driver, as a subtest named after it,
// with the server options that select that driver.
func forEachFlowDriver(t *testing.T, fn func(t *testing.T, o []server.Option)) {
	t.Helper()
	for _, d := range flowDrivers() {
		t.Run(d.name, func(t *testing.T) { fn(t, d.opts) })
	}
}

// flowNew starts the service on the driver o selects, with extra options.
func flowNew(t *testing.T, o []server.Option, opts ...server.Option) *server.Env {
	t.Helper()
	return server.New(t, append(slices.Clone(o), opts...)...)
}
