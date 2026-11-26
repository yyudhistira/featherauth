package config_test

import (
	"slices"
	"testing"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
)

// The shared rate limit needs Postgres: rate_limit.store database with the
// default SQLite driver is a configuration error, reported by config check and
// by the loader at startup.
//
// Covers: FR-53 (part)
// Acceptance: Shared rate limit (part)
func TestSharedRateLimitNeedsDriverPostgres(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A0", "")
	d.write("server.yaml", "public_url: https://auth.example.com\nrate_limit:\n  store: database\n", 0o600)

	var fields []string
	for _, diag := range config.Check(t.Context(), d.root, clock.Real()) {
		if diag.Severity == config.Error && diag.Field == "rate_limit.store" && diag.Line == 3 {
			fields = append(fields, diag.Field)
		}
	}
	if !slices.Equal(fields, []string{"rate_limit.store"}) {
		t.Fatalf("config check reports %v, want one error at rate_limit.store on line 3", fields)
	}
	if _, err := config.NewLoader(d.root, clock.NewFake(testStart), nil); err == nil {
		t.Fatal("startup accepted rate_limit.store database with SQLite")
	}
}

// The memory store is the default and needs no database.yaml.
//
// Covers: FR-53 (part)
func TestRateLimitStoreDefaultsToMemory(t *testing.T) {
	s, ds := config.DecodeServer("server.yaml", []byte("public_url: https://auth.example.com\n"))
	if s == nil || len(errorsOf(ds)) != 0 || s.RateLimit.Store != "memory" {
		t.Fatalf("store %q, diagnostics %v", s.RateLimit.Store, ds)
	}
}
