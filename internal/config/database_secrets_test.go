package config_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// writeDBSecret writes a file under dir with mode, after the umask.
func writeDBSecret(t *testing.T, dir, name string, content []byte, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// decodeDB decodes a database.yaml text and fails the test on any diagnostic.
func decodeDB(t *testing.T, yaml string) *config.DatabaseFile {
	t.Helper()
	db, ds := config.DecodeDatabase("database.yaml", []byte(yaml))
	for _, d := range ds {
		if d.Severity == config.Error {
			t.Fatalf("database.yaml: %v", d)
		}
	}
	return db
}

// pgYAML is a postgres database.yaml with the given sslmode and extra lines
// (indented under postgres).
func pgYAML(sslmode, extra string) string {
	return "driver: postgres\npostgres:\n  host: db.example.com\n  password_file: secrets/pg\n  sslmode: " + sslmode + "\n" + extra
}

const dbSecretPassword = "database-secret-password"

// Covers: FR-25 (part), SEC-09 (part)
// Acceptance: Postgres service (part)
func TestReadDatabaseSecrets(t *testing.T) {
	ca := testutil.NewAuthority(t)
	keyPEM := testutil.RSAKeyPEM(t)
	type file struct {
		content []byte
		mode    os.FileMode
	}
	pw := func(text string, mode os.FileMode) map[string]file {
		return map[string]file{"secrets/pg": {[]byte(text), mode}}
	}
	tests := []struct {
		name         string
		yaml         string
		files        map[string]file
		strict       bool
		wantPassword string // "" when a diagnostic is an error: a failed read returns no secrets
		wantCA       bool
		wantField    string // the one diagnostic expected; empty for none
		wantSeverity config.Severity
	}{
		{
			name:         "sqlite reads no secret",
			yaml:         "driver: sqlite\n",
			wantPassword: "",
		},
		{
			name:         "the password is read and one trailing newline dropped",
			yaml:         pgYAML("require", ""),
			files:        pw(dbSecretPassword+"\n", 0o600),
			strict:       true,
			wantPassword: dbSecretPassword,
		},
		{
			name:         "an empty password file is an error",
			yaml:         pgYAML("require", ""),
			files:        pw("\n", 0o600),
			strict:       true,
			wantField:    "postgres.password_file",
			wantSeverity: config.Error,
		},
		{
			name:         "a missing password file is an error",
			yaml:         pgYAML("require", ""),
			strict:       true,
			wantField:    "postgres.password_file",
			wantSeverity: config.Error,
		},
		{
			name:         "a password file readable by others is an error with strict permissions",
			yaml:         pgYAML("require", ""),
			files:        pw(dbSecretPassword, 0o644),
			strict:       true,
			wantField:    "postgres.password_file",
			wantSeverity: config.Error,
		},
		{
			name:         "a password file readable by others is a warning without strict permissions",
			yaml:         pgYAML("require", ""),
			files:        pw(dbSecretPassword, 0o644),
			strict:       false,
			wantPassword: dbSecretPassword,
			wantField:    "postgres.password_file",
			wantSeverity: config.Warning,
		},
		{
			name:         "require ignores a root certificate file that is missing",
			yaml:         pgYAML("require", "  root_cert_file: missing.pem\n"),
			files:        pw(dbSecretPassword, 0o600),
			strict:       true,
			wantPassword: dbSecretPassword,
		},
		{
			name:         "disable ignores a root certificate file that is missing",
			yaml:         pgYAML("disable", "  root_cert_file: missing.pem\n"),
			files:        pw(dbSecretPassword, 0o600),
			strict:       true,
			wantPassword: dbSecretPassword,
		},
		{
			name:         "verify-full with a root certificate file that is missing is an error",
			yaml:         pgYAML("verify-full", "  root_cert_file: ca.pem\n"),
			files:        pw(dbSecretPassword, 0o600),
			strict:       true,
			wantField:    "postgres.root_cert_file",
			wantSeverity: config.Error,
		},
		{
			name: "verify-full with a root certificate file that holds no certificate is an error",
			yaml: pgYAML("verify-full", "  root_cert_file: ca.pem\n"),
			files: map[string]file{
				"secrets/pg": {[]byte(dbSecretPassword), 0o600},
				"ca.pem":     {keyPEM, 0o644},
			},
			strict:       true,
			wantField:    "postgres.root_cert_file",
			wantSeverity: config.Error,
		},
		{
			name: "verify-full with a certificate authority reads it",
			yaml: pgYAML("verify-full", "  root_cert_file: ca.pem\n"),
			files: map[string]file{
				"secrets/pg": {[]byte(dbSecretPassword), 0o600},
				"ca.pem":     {ca.PEM, 0o644}, // a public certificate: no permission check
			},
			strict:       true,
			wantPassword: dbSecretPassword,
			wantCA:       true,
		},
		{
			name:         "verify-full without a root certificate file uses the system store",
			yaml:         pgYAML("verify-full", ""),
			files:        pw(dbSecretPassword, 0o600),
			strict:       true,
			wantPassword: dbSecretPassword,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, f := range tc.files {
				writeDBSecret(t, dir, name, f.content, f.mode)
			}
			got, ds := config.ReadDatabaseSecrets(dir, "database.yaml", decodeDB(t, tc.yaml), tc.strict)
			for _, d := range ds {
				if strings.Contains(d.String(), dbSecretPassword) {
					t.Fatalf("a diagnostic holds the password: %v", d)
				}
			}
			if tc.wantField == "" {
				if len(ds) != 0 {
					t.Fatalf("diagnostics = %v, want none", ds)
				}
			} else {
				if len(ds) != 1 || ds[0].Field != tc.wantField || ds[0].Severity != tc.wantSeverity || ds[0].File != "database.yaml" || ds[0].Line == 0 {
					t.Fatalf("diagnostics = %v, want one %s at %s", ds, tc.wantSeverity, tc.wantField)
				}
			}
			if got.Password() != tc.wantPassword {
				t.Errorf("Password() = %q, want %q", got.Password(), tc.wantPassword)
			}
			if (got.RootCAs() != nil) != tc.wantCA {
				t.Errorf("RootCAs() set = %v, want %v", got.RootCAs() != nil, tc.wantCA)
			}
		})
	}
}

// Covers: FR-25 (part), SEC-09 (part)
// Acceptance: Postgres service (part)
func TestReadDatabaseSecretsRootCertificateVerifiesTheAuthorityServers(t *testing.T) {
	ca := testutil.NewAuthority(t)
	other := testutil.NewAuthority(t)
	dir := t.TempDir()
	writeDBSecret(t, dir, "secrets/pg", []byte(dbSecretPassword), 0o600)
	writeDBSecret(t, dir, "ca.pem", ca.PEM, 0o644)
	got, ds := config.ReadDatabaseSecrets(dir, "database.yaml",
		decodeDB(t, pgYAML("verify-full", "  root_cert_file: ca.pem\n")), true)
	if len(ds) != 0 {
		t.Fatalf("diagnostics = %v", ds)
	}
	leaf := x509Leaf(t, ca.ServerCertificate(t, "db.example.com"))
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: got.RootCAs(), DNSName: "db.example.com"}); err != nil {
		t.Fatalf("the authority's server certificate does not verify: %v", err)
	}
	otherPool := x509.NewCertPool()
	if !otherPool.AppendCertsFromPEM(other.PEM) {
		t.Fatal("the other authority's PEM holds no certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: otherPool, DNSName: "db.example.com"}); err == nil {
		t.Fatal("a server certificate verified against another authority")
	}
}

// Covers: SEC-13 (part)
func TestDatabaseSecretsLogNoPassword(t *testing.T) {
	dir := t.TempDir()
	writeDBSecret(t, dir, "secrets/pg", []byte(dbSecretPassword+"\n"), 0o600)
	s, ds := config.ReadDatabaseSecrets(dir, "database.yaml", decodeDB(t, pgYAML("require", "")), true)
	if len(ds) != 0 || s.Password() != dbSecretPassword {
		t.Fatalf("diagnostics = %v, password set = %v", ds, s.Password() != "")
	}
	var buf bytes.Buffer
	l := logx.New(&buf, slog.LevelInfo, clock.NewFake(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)))
	l.Info("direct", "db", s)
	l.Info("nested", "details", map[string]any{"db": s, "inner": map[string]any{"x": s}})
	out := buf.String()
	if strings.Contains(out, dbSecretPassword) {
		t.Fatalf("the log holds the password: %s", out)
	}
	if !strings.Contains(out, "password_set") {
		t.Fatalf("the log does not say what the secrets hold: %s", out)
	}
}

// x509Leaf parses the leaf certificate of a TLS certificate of a test.
func x509Leaf(t *testing.T, c tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
