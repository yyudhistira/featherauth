package store_test

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

const connPassword = "conn-config-sentinel-password"

// connFixture writes the password file and the authority's certificate in a
// configuration directory and decodes a postgres database.yaml with the given
// sslmode and extra lines. It returns the postgres block and the secrets read
// for it, as serve reads them at startup.
func connFixture(t *testing.T, sslmode, extra string) (config.PostgresConfig, config.DatabaseSecrets) {
	t.Helper()
	dir := t.TempDir()
	writeSecret(t, dir, "secrets/pg", connPassword+"\n", 0o600)
	writeSecret(t, dir, "ca.pem", string(testutil.NewAuthority(t).PEM), 0o644)
	yaml := "driver: postgres\npostgres:\n  host: db.example.com\n  port: 5433\n  database: fa\n  user: fauser\n  password_file: secrets/pg\n  sslmode: " + sslmode + "\n" + extra
	db, ds := config.DecodeDatabase("database.yaml", []byte(yaml))
	if db == nil || len(ds) != 0 {
		t.Fatalf("decode: %v", ds)
	}
	secrets, ds := config.ReadDatabaseSecrets(dir, "database.yaml", db, true)
	if len(ds) != 0 {
		t.Fatalf("secrets: %v", ds)
	}
	return db.Postgres, secrets
}

func writeSecret(t *testing.T, dir, name, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// Covers: FR-35 (part), FR-25 (part)
// Acceptance: Postgres service (part)
func TestPostgresConnConfigFollowsSSLMode(t *testing.T) {
	tests := []struct {
		name        string
		sslmode     string
		extra       string
		wantTLS     bool
		wantSkipVer bool // require: TLS without verification
		wantRootCA  bool // verify-full with a root_cert_file
		wantServer  string
	}{
		{name: "disable", sslmode: "disable"},
		{name: "require", sslmode: "require", wantTLS: true, wantSkipVer: true},
		{name: "require ignores a root certificate", sslmode: "require", extra: "  root_cert_file: ca.pem\n", wantTLS: true, wantSkipVer: true},
		{name: "verify-full with the authority", sslmode: "verify-full", extra: "  root_cert_file: ca.pem\n", wantTLS: true, wantRootCA: true, wantServer: "db.example.com"},
		{name: "verify-full with the system store", sslmode: "verify-full", wantTLS: true, wantServer: "db.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pg, secrets := connFixture(t, tc.sslmode, tc.extra)
			cc, err := store.PostgresConnConfig(pg, secrets)
			if err != nil {
				t.Fatal(err)
			}
			if cc.Host != "db.example.com" || cc.Port != 5433 || cc.Database != "fa" || cc.User != "fauser" || cc.Password != connPassword {
				t.Errorf("connection = host %q port %d database %q user %q", cc.Host, cc.Port, cc.Database, cc.User)
			}
			if len(cc.Fallbacks) != 0 {
				t.Errorf("fallbacks = %d; sslmode must not fall back to a plain connection", len(cc.Fallbacks))
			}
			if (cc.TLSConfig != nil) != tc.wantTLS {
				t.Fatalf("TLS = %v, want %v", cc.TLSConfig != nil, tc.wantTLS)
			}
			if cc.TLSConfig == nil {
				return
			}
			checkTLS(t, cc.TLSConfig, tc.wantSkipVer, tc.wantRootCA, tc.wantServer, secrets.RootCAs())
		})
	}
}

func checkTLS(t *testing.T, c *tls.Config, skipVerify, rootCA bool, server string, pool any) {
	t.Helper()
	if c.InsecureSkipVerify != skipVerify {
		t.Errorf("InsecureSkipVerify = %v, want %v", c.InsecureSkipVerify, skipVerify)
	}
	if c.ServerName != server {
		t.Errorf("ServerName = %q, want %q", c.ServerName, server)
	}
	if (c.RootCAs != nil) != rootCA {
		t.Errorf("RootCAs set = %v, want %v", c.RootCAs != nil, rootCA)
	}
	if rootCA && c.RootCAs != pool {
		t.Error("RootCAs is not the pool of the root_cert_file")
	}
}

// Covers: FR-35 (part), SEC-13 (part)
// Acceptance: Postgres service (part)
func TestPostgresConnConfigErrorsHoldNoPassword(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sslmode string
		port    int
	}{
		{name: "unknown sslmode", sslmode: "prefer", port: 5433},
		{name: "port zero", sslmode: "disable", port: 0},
		{name: "port too large", sslmode: "disable", port: 70000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pg, secrets := connFixture(t, tc.sslmode, "")
			pg.Port = tc.port
			_, err := store.PostgresConnConfig(pg, secrets)
			if err == nil {
				t.Fatal("no error")
			}
			if strings.Contains(err.Error(), connPassword) {
				t.Fatalf("the error holds the password: %v", err)
			}
		})
	}
}

// The connection of the pool and of /readyz is opened with
// postgres.connect_timeout, which pgx applies to the TCP connect, TLS and the
// login together (OPS-22).
//
// Covers: FR-25 (part)
// Acceptance: Postgres connect timeout (part)
func TestPostgresConnConfigUsesTheConnectTimeout(t *testing.T) {
	for _, tc := range []struct {
		extra string
		want  time.Duration
	}{
		{"", 5 * time.Second},
		{"  connect_timeout: 2s\n", 2 * time.Second},
		{"  connect_timeout: 500ms\n", 500 * time.Millisecond},
	} {
		pg, secrets := connFixture(t, "disable", tc.extra)
		cc, err := store.PostgresConnConfig(pg, secrets)
		if err != nil {
			t.Fatal(err)
		}
		if cc.ConnectTimeout != tc.want {
			t.Errorf("extra %q: ConnectTimeout = %v, want %v", tc.extra, cc.ConnectTimeout, tc.want)
		}
	}
}
