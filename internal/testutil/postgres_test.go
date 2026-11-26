//go:build postgres

package testutil

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// postgresChildEnv marks the subprocess of TestNewPostgresStoreFailsWithoutEnv.
const postgresChildEnv = "FEATHERAUTH_TESTUTIL_POSTGRES_CHILD"

// Without the variable NewPostgresStore fails the test and never skips. A
// failing test cannot be observed in process, so the failing call runs in a
// subprocess (this test binary, with only this test) that has the variable
// removed, and the parent expects a non-zero exit with the reason in its output.
func TestNewPostgresStoreFailsWithoutEnv(t *testing.T) {
	if os.Getenv(postgresChildEnv) == "1" {
		NewPostgresStore(t)
		return
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, PostgresEnv+"=") {
			env = append(env, kv)
		}
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestNewPostgresStoreFailsWithoutEnv$")
	cmd.Env = append(env, postgresChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the subprocess passed without %s; output:\n%s", PostgresEnv, out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run the subprocess: %v", err)
	}
	if !strings.Contains(string(out), PostgresEnv+" is not set") {
		t.Errorf("output does not name %s:\n%s", PostgresEnv, out)
	}
}

// The connection string comes from the environment and is required: an unset or
// empty variable is an error, and the tests never skip.
func TestPostgresDSN(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		set     bool
		wantErr bool
	}{
		{name: "unset", set: false, wantErr: true},
		{name: "empty", value: "", set: true, wantErr: true},
		{name: "set", value: "postgres://u:p@127.0.0.1:5432/db?sslmode=disable", set: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(key string) (string, bool) {
				if key != PostgresEnv {
					t.Errorf("read %q, want %q", key, PostgresEnv)
				}
				return tc.value, tc.set
			}
			dsn, err := postgresDSN(lookup)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("postgresDSN() = %q, want an error", dsn)
				}
				if !strings.Contains(err.Error(), PostgresEnv) {
					t.Errorf("error %q does not name %s", err, PostgresEnv)
				}
				return
			}
			if err != nil {
				t.Fatalf("postgresDSN() error = %v", err)
			}
			if dsn != tc.value {
				t.Errorf("dsn = %q, want %q", dsn, tc.value)
			}
		})
	}
}

// The harness connects to the Postgres that make postgres starts, and that
// server is one of the supported versions (Postgres 15 or newer).
func TestPostgresConnection(t *testing.T) {
	db := NewPostgresDB(t)
	ctx := t.Context()
	var one int
	if err := db.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		t.Fatal(err)
	}
	if one != 1 {
		t.Fatalf("SELECT 1 = %d", one)
	}
	var num int
	if err := db.QueryRowContext(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&num); err != nil {
		t.Fatal(err)
	}
	if num < 150000 {
		t.Fatalf("server_version_num = %d, want Postgres 15 or newer", num)
	}
}
