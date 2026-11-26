package config_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/testutil"
)

// A new root certificate authority file is a database.yaml change: the service
// reports restart required and keeps the running value until it restarts.
// Covers: FR-18 (part), FR-25 (part)
// Acceptance: Postgres service (part)
func TestPostgresRootCertChangeNeedsARestart(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A", "")
	ca := testutil.NewAuthority(t)
	d.write("secrets/pg", "pw\n", 0o600)
	d.write("ca.pem", string(ca.PEM), 0o644)
	d.write("ca2.pem", string(ca.PEM), 0o644)
	d.write("database.yaml", "driver: postgres\npostgres:\n  host: db.example.com\n  password_file: secrets/pg\n  sslmode: verify-full\n  root_cert_file: ca.pem\n", 0o600)
	l, _, _ := d.loader(t)
	if got := l.Current().Database().Postgres.RootCertFile; got != "ca.pem" {
		t.Fatalf("root_cert_file = %q at start", got)
	}

	d.write("database.yaml", "driver: postgres\npostgres:\n  host: db.example.com\n  password_file: secrets/pg\n  sslmode: verify-full\n  root_cert_file: ca2.pem\n", 0o600)
	res := l.Reload(context.Background())
	if want := []string{"database.yaml:postgres.root_cert_file"}; !reflect.DeepEqual(res.RestartRequired, want) {
		t.Fatalf("RestartRequired = %v, want %v", res.RestartRequired, want)
	}
	if got := l.Current().Database().Postgres.RootCertFile; got != "ca.pem" {
		t.Errorf("root_cert_file = %q after the change; the running value must stay until a restart", got)
	}
}

// postgres.connect_timeout is read at startup: a changed value is reported as
// restart required and the running value stays; 2s is accepted.
// Covers: FR-18 (part), FR-25 (part)
// Acceptance: Postgres connect timeout (part)
func TestPostgresConnectTimeoutChangeNeedsARestart(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A", "")
	d.write("secrets/pg", "pw\n", 0o600)
	yaml := func(extra string) string {
		return "driver: postgres\npostgres:\n  host: db.example.com\n  password_file: secrets/pg\n" + extra
	}
	d.write("database.yaml", yaml("  connect_timeout: 2s\n"), 0o600)
	l, _, _ := d.loader(t)
	if got := l.Current().Database().Postgres.ConnectTimeout.Std(); got != 2*time.Second {
		t.Fatalf("connect_timeout = %v at start, want 2s", got)
	}

	d.write("database.yaml", yaml("  connect_timeout: 3s\n"), 0o600)
	res := l.Reload(context.Background())
	if want := []string{"database.yaml:postgres.connect_timeout"}; !reflect.DeepEqual(res.RestartRequired, want) {
		t.Fatalf("RestartRequired = %v, want %v", res.RestartRequired, want)
	}
	if got := l.Current().Database().Postgres.ConnectTimeout.Std(); got != 2*time.Second {
		t.Errorf("connect_timeout = %v after the change; the running value must stay until a restart", got)
	}
}
