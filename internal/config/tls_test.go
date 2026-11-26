package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil/tlscert"
)

// tlsServer is a server.yaml that serves TLS from files. The rows below change
// it with with and without.
const tlsServer = `public_url: https://auth.example.com
listen: "127.0.0.1:8080"
tls:
  mode: files
  listen: ":8443"
  http_listen: ":8081"
  cert_file: secrets/tls_cert.pem
  key_file: secrets/tls_key.pem
`

func withTLS(old, new string) string {
	if !strings.Contains(tlsServer, old) {
		panic("tlsServer has no " + old)
	}
	return strings.Replace(tlsServer, old, new, 1)
}

func withoutTLS(line string) string { return withTLS(line, "") }

func tlsErrors(ds []config.Diagnostic) []config.Diagnostic {
	var out []config.Diagnostic
	for _, d := range ds {
		if d.Severity == config.Error {
			out = append(out, d)
		}
	}
	return out
}

// Covers: FR-52, SEC-41 (part)
// Acceptance: Built-in TLS with files (part)
func TestTLSFilesOptionRules(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		field string // the one error, empty for none
		line  int    // its line, 0 when not checked
	}{
		{name: "valid", yaml: tlsServer},
		{name: "mode none needs no files", yaml: "public_url: https://auth.example.com\nlisten: \":8080\"\ntls:\n  mode: none\n"},
		{name: "empty http_listen opens no redirect", yaml: withTLS(`http_listen: ":8081"`, `http_listen: ""`)},
		{name: "public_url http with require_https false", yaml: withTLS("https://auth", "http://auth") + "require_https: false\n", field: "public_url", line: 1},
		{name: "public_url http with require_https true", yaml: withTLS("https://auth", "http://auth"), field: "public_url", line: 1},
		{name: "listen on all addresses", yaml: withTLS(`listen: "127.0.0.1:8080"`, `listen: ":8080"`), field: "listen", line: 2},
		{name: "listen on 0.0.0.0", yaml: withTLS(`listen: "127.0.0.1:8080"`, `listen: "0.0.0.0:8080"`), field: "listen", line: 2},
		{name: "listen on a host name", yaml: withTLS(`listen: "127.0.0.1:8080"`, `listen: "localhost:8080"`), field: "listen", line: 2},
		{name: "no key_file", yaml: withoutTLS("  key_file: secrets/tls_key.pem\n"), field: "tls.key_file"},
		{name: "no cert_file", yaml: withoutTLS("  cert_file: secrets/tls_cert.pem\n"), field: "tls.cert_file"},
		{name: "trusted_proxies set", yaml: tlsServer + "trusted_proxies: [\"127.0.0.1/32\"]\n", field: "trusted_proxies"},
		{name: "unknown mode", yaml: withTLS("mode: files", "mode: maybe"), field: "tls.mode", line: 4},
		{name: "tls.listen without a port", yaml: withTLS(`listen: ":8443"`, `listen: "8443"`), field: "tls.listen", line: 5},
		{name: "tls.http_listen without a port", yaml: withTLS(`http_listen: ":8081"`, `http_listen: "port"`), field: "tls.http_listen", line: 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, ds := config.DecodeServer("server.yaml", []byte(tt.yaml))
			if s == nil || len(tlsErrors(ds)) != 0 {
				t.Fatalf("decoding: %v", ds)
			}
			errs := tlsErrors(config.ValidateServer("server.yaml", s))
			if tt.field == "" {
				if len(errs) != 0 {
					t.Fatalf("errors %v, want none", errs)
				}
				return
			}
			if len(errs) != 1 || errs[0].Field != tt.field {
				t.Fatalf("errors %v, want one at %s", errs, tt.field)
			}
			if tt.line != 0 && errs[0].Line != tt.line {
				t.Errorf("error at line %d, want %d: %v", errs[0].Line, tt.line, errs[0])
			}
		})
	}
}

// writeTLSTestFile writes data to dir/name with exactly mode (the umask does not apply).
func writeTLSTestFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// decodeTLSServer decodes a server.yaml of the TLS rows, with strict_permissions as given.
func decodeTLSServer(t *testing.T, yaml string) *config.ServerFile {
	t.Helper()
	s, ds := config.DecodeServer("server.yaml", []byte(yaml))
	if s == nil || len(tlsErrors(ds)) != 0 {
		t.Fatalf("decoding: %v", ds)
	}
	return s
}

// Covers: SEC-41 (part), SEC-09 (part)
// Acceptance: Built-in TLS with files (part)
func TestTLSKeyFileIsASecretFile(t *testing.T) {
	tests := []struct {
		name    string
		mode    os.FileMode
		strict  string // the strict_permissions line
		wantErr bool
		warned  bool
	}{
		{name: "0600 under strict_permissions", mode: 0o600, wantErr: false},
		{name: "0644 under strict_permissions", mode: 0o644, wantErr: true},
		{name: "0644 without strict_permissions", mode: 0o644, strict: "strict_permissions: false\n", warned: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			pair := tlscert.New(t, "auth.example.com")
			writeTLSTestFile(t, dir, "secrets/tls_cert.pem", pair.CertPEM, 0o644)
			writeTLSTestFile(t, dir, "secrets/tls_key.pem", pair.KeyPEM, tt.mode)
			s := decodeTLSServer(t, tlsServer+tt.strict)
			cert, ds := config.LoadTLSPair(dir, s)
			errs := tlsErrors(ds)
			switch {
			case tt.wantErr:
				if cert != nil || len(errs) != 1 || errs[0].Field != "tls.key_file" {
					t.Fatalf("cert %v, diagnostics %v; want the key file refused", cert != nil, ds)
				}
			default:
				if len(errs) != 0 || cert == nil {
					t.Fatalf("cert %v, diagnostics %v; want the pair loaded", cert != nil, ds)
				}
			}
			warned := false
			for _, d := range ds {
				warned = warned || (d.Severity == config.Warning && d.Field == "tls.key_file")
			}
			if warned != tt.warned {
				t.Errorf("warning %v, want %v: %v", warned, tt.warned, ds)
			}
		})
	}
}

// Covers: SEC-41 (part)
// Acceptance: Built-in TLS with files (part)
func TestTLSPairMustBeLoadable(t *testing.T) {
	good := tlscert.New(t, "auth.example.com")
	other := tlscert.New(t, "other.example.com")
	tests := []struct {
		name  string
		cert  []byte
		key   []byte
		drop  string // a file that is not written
		field string // the one error, empty for none
	}{
		{name: "a matching pair", cert: good.CertPEM, key: good.KeyPEM},
		{name: "certificate file missing", cert: good.CertPEM, key: good.KeyPEM, drop: "secrets/tls_cert.pem", field: "tls.cert_file"},
		{name: "key file missing", cert: good.CertPEM, key: good.KeyPEM, drop: "secrets/tls_key.pem", field: "tls.key_file"},
		{name: "key of another certificate", cert: good.CertPEM, key: other.KeyPEM, field: "tls.key_file"},
		{name: "certificate is not PEM", cert: []byte("not a certificate"), key: good.KeyPEM, field: "tls.key_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.drop != "secrets/tls_cert.pem" {
				writeTLSTestFile(t, dir, "secrets/tls_cert.pem", tt.cert, 0o644)
			}
			if tt.drop != "secrets/tls_key.pem" {
				writeTLSTestFile(t, dir, "secrets/tls_key.pem", tt.key, 0o600)
			}
			s := decodeTLSServer(t, tlsServer)
			cert, ds := config.LoadTLSPair(dir, s)
			errs := tlsErrors(ds)
			if tt.field == "" {
				if len(errs) != 0 || cert == nil {
					t.Fatalf("cert %v, diagnostics %v; want the pair", cert != nil, ds)
				}
				return
			}
			if cert != nil || len(errs) != 1 || errs[0].Field != tt.field {
				t.Fatalf("cert %v, diagnostics %v; want one error at %s", cert != nil, ds, tt.field)
			}
			if strings.Contains(errs[0].Message, "PRIVATE KEY") || strings.Contains(errs[0].Message, "BEGIN") {
				t.Errorf("the diagnostic holds key or certificate bytes: %q", errs[0].Message)
			}
		})
	}
}

// The configuration check of the loader holds the files too: a server.yaml
// whose pair is missing is not loaded, and the secret rules see the key.
//
// Covers: SEC-41 (part)
// Acceptance: Built-in TLS with files (part)
func TestTLSFilesAreCheckedWithTheSecrets(t *testing.T) {
	dir := t.TempDir()
	s := decodeTLSServer(t, tlsServer)
	_, ds := config.LoadSecrets(dir, config.SecretSources{ServerFile: "server.yaml", Server: s})
	var fields []string
	for _, d := range tlsErrors(ds) {
		fields = append(fields, d.Field)
	}
	if len(fields) != 2 || fields[0] != "tls.cert_file" || fields[1] != "tls.key_file" {
		t.Fatalf("error fields %v, want the certificate and the key", fields)
	}
}

// A reload does not read the TLS pair: a pair broken after startup is not a
// configuration error of the reload (the certificate reloader keeps the previous
// pair). Startup still refuses a broken pair.
//
// Covers: FR-52 (part), SEC-41 (part)
func TestReloadDoesNotRejectTheTLSPair(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A0", "")
	pair := tlscert.New(t, "auth.example.com")
	d.write("secrets/tls_cert.pem", string(pair.CertPEM), 0o644)
	d.write("secrets/tls_key.pem", string(pair.KeyPEM), 0o600)
	d.write("server.yaml", tlsServer, 0o600)
	l, _, _ := d.loader(t)

	d.write("secrets/tls_cert.pem", "not a certificate\n", 0o644)
	res := l.Reload(t.Context())
	if !res.Applied {
		t.Fatalf("the reload was not applied: %v", res.Diagnostics)
	}
	if errs := errorsOf(res.Diagnostics); len(errs) != 0 {
		t.Fatalf("a reload reports the TLS pair: %v", errs)
	}

	if _, err := config.NewLoader(d.root, clock.NewFake(testStart), nil); err == nil {
		t.Fatal("startup accepted a broken TLS pair")
	}
}
