package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// sentinel is a recognizable secret text; no diagnostic or log may hold it.
const sentinel = "SENTINEL-s3cr3t-value-9f2c"

func writeFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func rsaPEM(t *testing.T, bits int) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(secure.Default, bits)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

func ecPEM(t *testing.T, c elliptic.Curve, pkcs8 bool) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func encKey(b byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)))
}

// webSecret is the client secret of the fixture. It has 32 characters or more,
// so that the fixture gives no client secret warning.
const webSecret = "web-client-secret-of-32-characters"

// fixture writes a config directory with one of every secret kind.
func fixture(t *testing.T, mode os.FileMode) (string, SecretSources) {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "keys/rsa.pem", rsaPEM(t, 2048), mode)
	writeFile(t, dir, "keys/ec.pem", ecPEM(t, elliptic.P256(), false), mode)
	writeFile(t, dir, "keys/apple.p8", ecPEM(t, elliptic.P256(), true), mode)
	writeFile(t, dir, "secrets/google", []byte("google-secret\n"), mode)
	writeFile(t, dir, "secrets/web", []byte(webSecret), mode)
	writeFile(t, dir, "secrets/enc1", append(encKey(1), '\n'), mode)
	writeFile(t, dir, "secrets/enc2", encKey(2), mode)

	srv := defaultServer()
	srv.Secrets.EncryptionKeyFiles = []string{"secrets/enc1", "secrets/enc2"}
	realm := defaultRealm()
	realm.Name = "main"
	realm.Keys = []Key{
		{Kid: "rsa1", File: "keys/rsa.pem", State: "active"},
		{Kid: "ec1", File: "keys/ec.pem", State: "active"},
	}
	realm.Providers = Providers{
		"google": &Provider{Type: "google", Enabled: true, ClientSecretFile: "secrets/google"},
		"apple":  &Provider{Type: "apple", Enabled: true, PrivateKeyFile: "keys/apple.p8"},
	}
	realm.Clients = Clients{"web": &Client{Type: Confidential, ClientSecretFile: "secrets/web"}}
	return dir, SecretSources{
		ServerFile: "server.yaml", Server: &srv,
		Realms: []RealmSource{{File: "realms/main.yaml", Realm: &realm}},
	}
}

func noErrors(t *testing.T, ds []Diagnostic) {
	t.Helper()
	for _, d := range ds {
		t.Errorf("unexpected diagnostic: %s", d)
	}
}

func TestLoadSecretsReadsEveryKind(t *testing.T) {
	dir, src := fixture(t, 0o600)
	s, ds := LoadSecrets(dir, src)
	noErrors(t, ds)
	if s == nil {
		t.Fatal("nil secrets")
	}
	if s.Signing("rsa1") == nil || s.Signing("ec1") == nil || s.Signing("nope") != nil {
		t.Error("signing keys wrong")
	}
	if s.AppleKey("main", "apple") == nil || s.AppleKey("main", "google") != nil {
		t.Error("apple key wrong")
	}
	if got := s.ClientSecret("main", ProviderSecret, "google"); got != "google-secret" {
		t.Errorf("provider secret %q", got)
	}
	if got := s.ClientSecret("main", ClientSecretOf, "web"); got != webSecret {
		t.Errorf("client secret %q", got)
	}
	if got := s.ClientSecret("main", ClientSecretOf, "none"); got != "" {
		t.Errorf("unknown client secret %q", got)
	}
	ek := s.EncryptionKeys()
	if len(ek) != 2 || !bytes.Equal(ek[0], bytes.Repeat([]byte{1}, 32)) || !bytes.Equal(ek[1], bytes.Repeat([]byte{2}, 32)) {
		t.Errorf("encryption keys wrong: %d", len(ek))
	}
	ek[0][0] = 99
	if s.EncryptionKeys()[0][0] != 1 {
		t.Error("EncryptionKeys exposes internal state")
	}
}

// Covers: SEC-09
// Acceptance: Strict permissions default (part)
func TestStrictPermissionsDefaultsToTrue(t *testing.T) {
	s, ds := DecodeServer("server.yaml", []byte("public_url: https://auth.example.com\n"))
	noErrors(t, ds)
	if !s.StrictPermissions {
		t.Fatal("strict_permissions is not true when server.yaml does not set it")
	}
	s, ds = DecodeServer("server.yaml", []byte("public_url: https://auth.example.com\nstrict_permissions: false\n"))
	noErrors(t, ds)
	if s.StrictPermissions {
		t.Fatal("strict_permissions: false is not read")
	}
}

// Covers: SEC-09
// Acceptance: Strict permissions default (part)
func TestPermissionsDefaultIsAnError(t *testing.T) {
	dir, src := fixture(t, 0o600)
	writeFile(t, dir, "secrets/google", []byte("google-secret\n"), 0o644)
	s, ds := LoadSecrets(dir, src)
	if s != nil || len(ds) != 1 || ds[0].Severity != Error || ds[0].File != "realms/main.yaml" ||
		ds[0].Field != "providers.google.client_secret_file" || !strings.Contains(ds[0].Message, "secrets/google") {
		t.Fatalf("with the default, a file at 0644 must be an error naming it: secrets %v, diagnostics %v", s != nil, ds)
	}
}

// Covers: SEC-09 (part)
// Acceptance: Secret file permissions and key sizes (part)
func TestPermissionsWarnOrErrorByMode(t *testing.T) {
	tests := []struct {
		name   string
		mode   os.FileMode
		strict bool
		want   Severity // 0 means clean
	}{
		{"0600 clean", 0o600, false, 0},
		{"0600 strict clean", 0o600, true, 0},
		{"0644 warns", 0o644, false, Warning},
		{"0640 warns", 0o640, false, Warning},
		{"0604 warns", 0o604, false, Warning},
		{"0644 strict errors", 0o644, true, Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, src := fixture(t, 0o600)
			writeFile(t, dir, "secrets/google", []byte("google-secret\n"), tt.mode)
			src.Server.StrictPermissions = tt.strict
			_, ds := LoadSecrets(dir, src)
			if tt.want == 0 {
				noErrors(t, ds)
				return
			}
			if len(ds) != 1 {
				t.Fatalf("want one diagnostic, got %v", ds)
			}
			d := ds[0]
			if d.Severity != tt.want || d.File != "realms/main.yaml" || d.Field != "providers.google.client_secret_file" ||
				!strings.Contains(d.Message, "secrets/google") {
				t.Errorf("got %s", d)
			}
		})
	}
}

// Covers: SEC-09 (part)
// Acceptance: Secret file permissions and key sizes (part)
func TestPermissionsCheckEveryFileOption(t *testing.T) {
	for _, name := range []string{"keys/rsa.pem", "keys/apple.p8", "secrets/web", "secrets/enc2"} {
		t.Run(name, func(t *testing.T) {
			dir, src := fixture(t, 0o600)
			src.Server.StrictPermissions = false
			p := filepath.Join(dir, name)
			if err := os.Chmod(p, 0o644); err != nil {
				t.Fatal(err)
			}
			_, ds := LoadSecrets(dir, src)
			if len(ds) != 1 || ds[0].Severity != Warning || !strings.Contains(ds[0].Message, name) {
				t.Fatalf("got %v", ds)
			}
		})
	}
}

func TestPermissionDiagnosticCarriesLine(t *testing.T) {
	dir, src := fixture(t, 0o600)
	realm, ds := DecodeRealm("realms/main.yaml", []byte("name: main\nkeys:\n  - kid: rsa1\n    file: keys/rsa.pem\n    state: active\n"))
	noErrors(t, ds)
	src.Realms = []RealmSource{{File: "realms/main.yaml", Realm: realm}}
	if err := os.Chmod(filepath.Join(dir, "keys/rsa.pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, ds = LoadSecrets(dir, src)
	if len(ds) != 1 || ds[0].Line != 4 || ds[0].Field != "keys[0].file" {
		t.Fatalf("got %v", ds)
	}
}

func TestPathsAreRelativeToConfigDir(t *testing.T) {
	dir, src := fixture(t, 0o600)
	abs := filepath.Join(dir, "secrets", "google")
	src.Realms[0].Realm.Providers["google"].ClientSecretFile = abs
	s, ds := LoadSecrets(dir, src)
	noErrors(t, ds)
	if s.ClientSecret("main", ProviderSecret, "google") != "google-secret" {
		t.Error("absolute path not read")
	}
}

// Covers: SEC-09 (part)
// Acceptance: Secret file permissions and key sizes (part)
func TestBadKeyMaterialIsRejected(t *testing.T) {
	small := rsaPEM(t, 1024)
	p384 := ecPEM(t, elliptic.P384(), false)
	rsaAsApple := rsaPEM(t, 2048)
	tests := []struct {
		name  string
		file  string
		data  []byte
		field string
		want  string
	}{
		{"not PEM", "keys/rsa.pem", []byte("not a pem " + sentinel), "keys[0].file", "PEM"},
		{"empty", "keys/rsa.pem", nil, "keys[0].file", "PEM"},
		{"1024-bit RSA", "keys/rsa.pem", small, "keys[0].file", "2048"},
		{"EC P-384 signing", "keys/ec.pem", p384, "keys[1].file", "P-256"},
		{"corrupt DER", "keys/rsa.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte(sentinel)}), "keys[0].file", "private key"},
		{"unknown block", "keys/rsa.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte(sentinel)}), "keys[0].file", "private key"},
		{"RSA as apple key", "keys/apple.p8", rsaAsApple, "providers.apple.private_key_file", "P-256"},
		{"apple not PEM", "keys/apple.p8", []byte(sentinel), "providers.apple.private_key_file", "PEM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, src := fixture(t, 0o600)
			writeFile(t, dir, tt.file, tt.data, 0o600)
			s, ds := LoadSecrets(dir, src)
			if s != nil {
				t.Error("secrets returned despite errors")
			}
			if len(ds) != 1 || ds[0].Severity != Error || ds[0].Field != tt.field || !strings.Contains(ds[0].Message, tt.want) {
				t.Fatalf("got %v", ds)
			}
			if strings.Contains(ds[0].String(), sentinel) {
				t.Error("diagnostic holds secret bytes")
			}
		})
	}
}

// Covers: SEC-09 (part)
// Acceptance: Secret file permissions and key sizes (part)
// Acceptance: Config validation (part)
func TestEncryptionKeyMustBe32BytesOfBase64(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31))
	long := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33))
	tests := []struct {
		name string
		data []byte
	}{
		{"31 bytes", []byte(short)},
		{"33 bytes", []byte(long)},
		{"not base64", []byte("!!!not-base64!!!" + sentinel)},
		{"raw 32 bytes", bytes.Repeat([]byte{7}, 32)},
		{"empty", nil},
		{"two newlines", append(encKey(1), '\n', '\n')},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, src := fixture(t, 0o600)
			writeFile(t, dir, "secrets/enc2", tt.data, 0o600)
			s, ds := LoadSecrets(dir, src)
			if s != nil {
				t.Error("secrets returned despite errors")
			}
			if len(ds) != 1 || ds[0].Severity != Error || ds[0].File != "server.yaml" ||
				ds[0].Field != "secrets.encryption_key_files[1]" || !strings.Contains(ds[0].Message, "32 bytes") {
				t.Fatalf("got %v", ds)
			}
			if strings.Contains(ds[0].String(), sentinel) {
				t.Error("diagnostic holds secret bytes")
			}
		})
	}
}

// Covers: SEC-09 (part)
// Acceptance: Secret file permissions and key sizes (part)
func TestSecretKeepsAllButOneTrailingNewline(t *testing.T) {
	// long pads the secret to 32 characters, so that only the newlines differ.
	long := strings.Repeat("k", 29)
	tests := []struct{ name, in, want string }{
		{"none", long + "abc", long + "abc"},
		{"one", long + "abc\n", long + "abc"},
		{"two", long + "abc\n\n", long + "abc\n"},
		{"inner", long + "a\nb\n", long + "a\nb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, src := fixture(t, 0o600)
			writeFile(t, dir, "secrets/web", []byte(tt.in), 0o600)
			s, ds := LoadSecrets(dir, src)
			noErrors(t, ds)
			if got := s.ClientSecret("main", ClientSecretOf, "web"); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMissingFileIsAnError(t *testing.T) {
	dir, src := fixture(t, 0o600)
	src.Realms[0].Realm.Clients["web"].ClientSecretFile = "secrets/absent"
	s, ds := LoadSecrets(dir, src)
	if s != nil || len(ds) != 1 || ds[0].Severity != Error || ds[0].Field != "clients.web.client_secret_file" ||
		!strings.Contains(ds[0].Message, "secrets/absent") {
		t.Fatalf("got %v", ds)
	}
}

func TestMissingEncryptionKeyOnlyMattersWithStoredTokens(t *testing.T) {
	dir, src := fixture(t, 0o600)
	src.Server.Secrets.EncryptionKeyFiles = []string{"secrets/absent"}
	s, ds := LoadSecrets(dir, src)
	noErrors(t, ds)
	if len(s.EncryptionKeys()) != 0 {
		t.Error("keys from a missing file")
	}
	src.Realms[0].Realm.Providers["apple"].StoreRefreshToken = true
	s, ds = LoadSecrets(dir, src)
	if s != nil || len(ds) != 1 || ds[0].Severity != Error || ds[0].Field != "secrets.encryption_key_files[0]" {
		t.Fatalf("got %v", ds)
	}
}

func TestUnsetFileOptionsAreSkipped(t *testing.T) {
	dir := t.TempDir()
	srv := defaultServer()
	realm := defaultRealm()
	realm.Providers = Providers{"github": &Provider{Type: "github"}}
	realm.Clients = Clients{"app": &Client{Type: Public}}
	s, ds := LoadSecrets(dir, SecretSources{ServerFile: "server.yaml", Server: &srv,
		Realms: []RealmSource{{File: "realms/main.yaml", Realm: &realm}}})
	noErrors(t, ds)
	if s == nil {
		t.Fatal("nil")
	}
}

func TestDatabasePasswordFilePermissionChecked(t *testing.T) {
	dir, src := fixture(t, 0o600)
	writeFile(t, dir, "secrets/pg", []byte("pw\n"), 0o644)
	src.Server.StrictPermissions = false
	db := defaultDatabase()
	db.Driver = "postgres"
	db.Postgres.PasswordFile = "secrets/pg"
	src.DatabaseFile, src.Database = "database.yaml", &db
	_, ds := LoadSecrets(dir, src)
	if len(ds) != 1 || ds[0].Severity != Warning || ds[0].File != "database.yaml" || ds[0].Field != "postgres.password_file" {
		t.Fatalf("got %v", ds)
	}
}

func TestSecretsImplementsInterface(t *testing.T) {
	dir, src := fixture(t, 0o600)
	s, _ := LoadSecrets(dir, src)
	var _ Secrets = s
}

// Covers: SEC-13 (part)
func TestSecretsLogsNoKeyMaterialOrSecret(t *testing.T) {
	dir, src := fixture(t, 0o600)
	writeFile(t, dir, "secrets/web", []byte(secretOf(32)+"\n"), 0o600)
	s, ds := LoadSecrets(dir, src)
	noErrors(t, ds)
	// the sentinel and every byte pattern of the key material
	forbidden := []string{sentinel, "google-secret", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), "PRIVATE KEY"}
	for _, k := range s.signing {
		switch k := k.(type) {
		case *rsa.PrivateKey:
			forbidden = append(forbidden, k.D.String())
		case *ecdsa.PrivateKey:
			if raw, err := k.Bytes(); err == nil {
				forbidden = append(forbidden, hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw))
			}
		}
	}

	cases := map[string]func(l *slog.Logger){
		"direct": func(l *slog.Logger) { l.Info("m", "loaded", s) },
		"nested map": func(l *slog.Logger) {
			l.Info("m", "details", map[string]any{"loaded": s, "inner": map[string]any{"x": s}})
		},
		"slice": func(l *slog.Logger) { l.Info("m", "list", []any{s}) },
		"group": func(l *slog.Logger) { l.Info("m", slog.Group("g", slog.Any("loaded", s))) },
	}
	for name, log := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			log(logx.New(&buf, slog.LevelDebug, clock.NewFake(time.Unix(0, 0))))
			out := buf.String()
			for _, want := range []string{`"signing_count":2`, `"encryption_count":2`, `"apple_count":1`, `"secret_count":2`} {
				if !strings.Contains(out, want) {
					t.Errorf("log lacks %s: %s", want, out)
				}
			}
			for _, f := range forbidden {
				if strings.Contains(out, f) {
					t.Errorf("log holds %q", f)
				}
			}
		})
	}
	var _ slog.LogValuer = Secrets(s)
}

// Covers: SEC-09 (part)
// Acceptance: Config validation (part)
func TestServerAndDatabaseFileLine(t *testing.T) {
	srv, ds := DecodeServer("server.yaml", []byte("public_url: https://a.example\nsecrets:\n  encryption_key_files:\n    - secrets/k1\n"))
	noErrors(t, ds)
	for field, want := range map[string]int{"public_url": 1, "secrets.encryption_key_files[0]": 4, "missing": 0} {
		if got := srv.Line(field); got != want {
			t.Errorf("server Line(%q) = %d, want %d", field, got, want)
		}
	}
	db, ds := DecodeDatabase("database.yaml", []byte("driver: postgres\npostgres:\n  host: h\n  password_file: secrets/pg\n"))
	noErrors(t, ds)
	for field, want := range map[string]int{"driver": 1, "postgres.password_file": 4, "missing": 0} {
		if got := db.Line(field); got != want {
			t.Errorf("database Line(%q) = %d, want %d", field, got, want)
		}
	}
}

// Covers: SEC-10 (part)
// Acceptance: Encryption key rotation (part)
// Acceptance: Config validation (part)
func TestEncryptionKeyRequiredOnlyByEnabledStoringProvider(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		store   bool
		wantErr bool
	}{
		{"enabled and storing", true, true, true},
		{"enabled, not storing", true, false, false},
		{"disabled and storing", false, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, src := fixture(t, 0o600)
			src.Server.Secrets.EncryptionKeyFiles = []string{"secrets/absent"}
			p := src.Realms[0].Realm.Providers["apple"]
			p.Enabled, p.StoreRefreshToken = tt.enabled, tt.store
			s, ds := LoadSecrets(dir, src)
			if !tt.wantErr {
				noErrors(t, ds)
				return
			}
			if s != nil || len(ds) != 1 || ds[0].Severity != Error || ds[0].Field != "secrets.encryption_key_files[0]" {
				t.Fatalf("got %v", ds)
			}
		})
	}
}

// Covers: SEC-09 (part)
// Acceptance: Config validation (part)
func TestDisabledProviderSecretsAreNotRead(t *testing.T) {
	dir, src := fixture(t, 0o600)
	g := src.Realms[0].Realm.Providers["google"]
	g.Enabled = false
	g.ClientSecretFile = "secrets/absent"
	a := src.Realms[0].Realm.Providers["apple"]
	a.Enabled = false
	a.PrivateKeyFile = "keys/absent.p8"
	if err := os.Chmod(filepath.Join(dir, "secrets/google"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, ds := LoadSecrets(dir, src)
	noErrors(t, ds)
	if s.ClientSecret("main", ProviderSecret, "google") != "" || s.AppleKey("main", "apple") != nil {
		t.Error("disabled provider secrets were loaded")
	}
}

// Covers: SEC-10 (part)
// Acceptance: Config validation (part)
func TestDisabledAppleWithDefaultsAndNoKeyFile(t *testing.T) {
	dir := t.TempDir()
	srv := defaultServer() // default key file secrets/encryption_key does not exist
	realm := defaultRealm()
	apple := defaultProvider("apple", "apple")
	apple.Enabled = false
	realm.Providers = Providers{"apple": &apple}
	s, ds := LoadSecrets(dir, SecretSources{ServerFile: "server.yaml", Server: &srv,
		Realms: []RealmSource{{File: "realms/main.yaml", Realm: &realm}}})
	noErrors(t, ds)
	if s == nil || len(s.EncryptionKeys()) != 0 {
		t.Fatal("want secrets without keys")
	}
}

// Covers: SEC-09 (part), FR-32 (part)
// Acceptance: Config validation (part)
func TestEmptyClientSecretFileIsAnError(t *testing.T) {
	for _, content := range []string{"", "\n", "  \n", "\t\n\n"} {
		for _, c := range []struct{ name, field, file string }{
			{"provider", "providers.google.client_secret_file", "secrets/google"},
			{"client", "clients.web.client_secret_file", "secrets/web"},
		} {
			t.Run(c.name+" "+strings.ReplaceAll(strings.ReplaceAll(content, "\n", `\n`), "\t", `\t`), func(t *testing.T) {
				dir, src := fixture(t, 0o600)
				writeFile(t, dir, c.file, []byte(content), 0o600)
				s, ds := LoadSecrets(dir, src)
				if s != nil || len(ds) != 1 || ds[0].Severity != Error || ds[0].Field != c.field ||
					!strings.Contains(ds[0].Message, c.file) || !strings.Contains(ds[0].Message, "empty") {
					t.Fatalf("got %v", ds)
				}
			})
		}
	}

	// a disabled provider's file is not read, so an empty one is accepted
	dir, src := fixture(t, 0o600)
	writeFile(t, dir, "secrets/google", nil, 0o600)
	src.Realms[0].Realm.Providers["google"].Enabled = false
	if _, ds := LoadSecrets(dir, src); len(ds) != 0 {
		t.Errorf("a disabled provider's empty secret file: %v", ds)
	}
}

// secretOf returns a secret of n characters that starts with the sentinel.
func secretOf(n int) string {
	return sentinel + strings.Repeat("x", n-len(sentinel))
}

// Covers: SEC-30
// Acceptance: Client secret length (part)
func TestClientSecretLengthWarning(t *testing.T) {
	const message = "secret file secrets/web is shorter than 32 characters; use a client secret of at least 32 characters"
	tests := []struct {
		name   string
		secret string
		eol    string // the line ending of the file: "\n", or "\r\n" for a file written on Windows
		warn   bool
	}{
		{"31 characters warns", secretOf(31), "\n", true},
		{"32 characters is clean", secretOf(32), "\n", false},
		{"31 characters, 62 bytes, warns", strings.Repeat("é", 31), "\n", true},
		{"32 characters, 64 bytes, is clean", strings.Repeat("é", 32), "\n", false},
		// Only one "\n" is dropped, so the CR stays in the secret: 31 characters
		// and a CRLF ending count as 32 and do not warn.
		{"31 characters with CRLF keeps its CR, clean", secretOf(31), "\r\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, src := fixture(t, 0o600)
			writeFile(t, dir, "secrets/web", []byte(tt.secret+tt.eol), 0o600)
			// the secret the service compares: the content without one trailing "\n"
			loaded := tt.secret + strings.TrimSuffix(tt.eol, "\n")
			s, ds := LoadSecrets(dir, src)
			if s == nil {
				t.Fatal("a short client secret must still load")
			}
			if got := s.ClientSecret("main", ClientSecretOf, "web"); got != loaded {
				t.Errorf("secret read as %q", got)
			}
			if !tt.warn {
				noErrors(t, ds)
				return
			}
			want := Diagnostic{
				File: "realms/main.yaml", Field: "clients.web.client_secret_file",
				Severity: Warning, Message: message,
			}
			if len(ds) != 1 || ds[0] != want {
				t.Fatalf("got %v, want %s", ds, want)
			}
			if strings.Contains(ds[0].String(), tt.secret) {
				t.Error("the warning holds the secret")
			}
		})
	}
}

// Covers: SEC-30
// Acceptance: Client secret length (part)
func TestClientSecretLengthCheckOnlyConfidentialClientSecrets(t *testing.T) {
	tests := []struct {
		name      string
		publicWeb bool // the client web is public, with a short secret file
	}{
		{"provider secret", false},
		{"public client", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, src := fixture(t, 0o600)
			writeFile(t, dir, "secrets/google", []byte("short\n"), 0o600)
			if tt.publicWeb {
				src.Realms[0].Realm.Clients["web"].Type = Public
				writeFile(t, dir, "secrets/web", []byte("short\n"), 0o600)
			}
			_, ds := LoadSecrets(dir, src)
			noErrors(t, ds)
		})
	}
}
