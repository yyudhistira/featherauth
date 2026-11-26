//go:build postgres

package store_test

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// openPostgres opens the store of a postgres database.yaml that reaches the
// database at pg, with the password in a password file of its own and, when
// rootPEM is set, the certificate authority in root_cert_file. It is what serve
// does at startup, through the same config functions.
func openPostgres(t *testing.T, pg config.PostgresConfig, password string, rootPEM []byte) (store.Store, error) {
	t.Helper()
	return openPostgresCtx(context.Background(), t, pg, password, rootPEM)
}

// openPostgresCtx is openPostgres with the context of the start.
func openPostgresCtx(ctx context.Context, t *testing.T, pg config.PostgresConfig, password string, rootPEM []byte) (store.Store, error) {
	t.Helper()
	dir := t.TempDir()
	writeSecret(t, dir, "secrets/pg", password+"\n", 0o600)
	pg.PasswordFile = "secrets/pg"
	yamlRoot := ""
	if rootPEM != nil {
		writeSecret(t, dir, "ca.pem", string(rootPEM), 0o644)
		pg.RootCertFile = "ca.pem"
		yamlRoot = "ca.pem"
	}
	db := &config.DatabaseFile{Driver: "postgres", Postgres: pg}
	secrets, ds := config.ReadDatabaseSecrets(dir, "database.yaml", db, true)
	for _, d := range ds {
		if d.Severity == config.Error {
			t.Fatalf("secrets: %v (root %q)", d, yamlRoot)
		}
	}
	s, err := store.Open(ctx, *db, secrets)
	if err == nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	return s, err
}

// Covers: FR-35 (part), FR-25 (part)
// Acceptance: Postgres service (part)
func TestOpenPostgresStartsAndPings(t *testing.T) {
	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	pg.Host, pg.Port = srv.Host, srv.Port
	s, err := openPostgres(t, pg, srv.Password, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

// The server's certificate is checked against the root certificate file: the
// right authority connects through TLS, a wrong one fails the start, and the
// error holds no password.
// Covers: FR-35 (part), FR-25 (part), SEC-13 (part)
// Acceptance: Postgres service (part)
func TestOpenPostgresVerifyFullUsesTheRootCertificateFile(t *testing.T) {
	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	right := testutil.NewAuthority(t)
	proxy := testutil.NewPostgresProxy(t, srv.Addr(), &tls.Config{
		Certificates: []tls.Certificate{right.ServerCertificate(t, "127.0.0.1")},
	})
	pg.Host, pg.Port, pg.SSLMode = "127.0.0.1", proxy.Port(), "verify-full"

	s, err := openPostgres(t, pg, srv.Password, right.PEM)
	if err != nil {
		t.Fatalf("the right authority: %v", err)
	}
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("ping over TLS: %v", err)
	}

	wrong := testutil.NewAuthority(t)
	_, err = openPostgres(t, pg, srv.Password, wrong.PEM)
	if err == nil {
		t.Fatal("the wrong authority started the store")
	}
	if strings.Contains(err.Error(), srv.Password) {
		t.Fatalf("the error holds the password: %v", err)
	}
}

// A wrong password fails the start with the server's login failure (SQLSTATE
// 28P01), and the error holds no password. The right password starts the store
// with the same configuration, so the failure is the password's and not the
// connection's.
// Covers: FR-35 (part), FR-25 (part), SEC-13 (part)
// Acceptance: Postgres service (part)
func TestOpenPostgresWrongPasswordHoldsNoPassword(t *testing.T) {
	srv := testutil.NewPostgresServer(t)
	pg := srv.NewDatabase(t)
	pg.Host, pg.Port = srv.Host, srv.Port
	right, err := openPostgres(t, pg, srv.Password, nil)
	if err != nil {
		t.Fatalf("the right password did not start the store: %v", err)
	}
	if err := right.Ping(context.Background()); err != nil {
		t.Fatalf("ping with the right password: %v", err)
	}
	wrong := "wrong-password-sentinel"
	_, err = openPostgres(t, pg, wrong, nil)
	if err == nil || !strings.Contains(err.Error(), "password authentication failed") {
		t.Fatalf("a wrong password is not refused as a login failure: %v", err)
	}
	if strings.Contains(err.Error(), wrong) || strings.Contains(err.Error(), srv.Password) {
		t.Fatalf("the error holds a password: %v", err)
	}
}
