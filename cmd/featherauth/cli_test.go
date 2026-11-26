package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/deploy"
	"github.com/yyudhistira/featherauth/internal/clock"
)

type result struct {
	code           int
	stdout, stderr string
}

// exec runs the CLI with the given environment.
func exec(t *testing.T, env map[string]string, args ...string) result {
	t.Helper()
	return execAt(t, clock.NewFake(time.Unix(0, 0)), env, args...)
}

// execAt is exec with a clock the test controls.
func execAt(t *testing.T, clk clock.Clock, env map[string]string, args ...string) result {
	t.Helper()
	return execApp(t, clk, env, nil, args...)
}

// execApp is execAt that lets the test change the app before it runs.
func execApp(t *testing.T, clk clock.Clock, env map[string]string, setup func(*app), args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	a := &app{
		stdout: &out, stderr: &errb, clock: clk,
		getenv:        func(k string) string { return env[k] },
		healthTimeout: 2 * time.Second,
	}
	if setup != nil {
		setup(a)
	}
	code := a.run(context.Background(), args)
	return result{code, out.String(), errb.String()}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// initDir runs config init and generates the signing key the example names,
// so the directory is a valid configuration.
func initDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "conf")
	if r := exec(t, nil, "config", "init", dir); r.code != 0 {
		t.Fatalf("config init: %+v", r)
	}
	key := filepath.Join(dir, "secrets/example/signing-2026-10.pem")
	if r := exec(t, nil, "keys", "generate", key); r.code != 0 {
		t.Fatalf("keys generate: %+v", r)
	}
	return dir
}

// Covers: FR-20 (part)
// Acceptance: CLI commands (part)
func TestConfigInitWritesTheExamples(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "conf")
	r := exec(t, nil, "config", "init", dir)
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("%+v", r)
	}
	n := 0
	err := fs.WalkDir(deploy.ConfigExample, "config.example", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n++
		want, _ := fs.ReadFile(deploy.ConfigExample, p)
		rel := strings.TrimPrefix(p, "config.example/")
		if got := read(t, filepath.Join(dir, rel)); got != string(want) {
			t.Errorf("%s differs from the shipped example", rel)
		}
		if !strings.Contains(r.stdout, rel) {
			t.Errorf("stdout does not name %s: %q", rel, r.stdout)
		}
		return nil
	})
	if err != nil || n != 5 {
		t.Fatalf("walked %d files, %v", n, err)
	}
	for _, rel := range []string{"server.yaml", "server.tls.yaml.example", "database.yaml", "realms/example.yaml", "locales/en.yaml.example"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Error(err)
		}
	}
}

// Covers: FR-20 (part)
// Acceptance: CLI commands (part)
func TestConfigInitRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	mine := filepath.Join(dir, "database.yaml")
	if err := os.WriteFile(mine, []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := exec(t, nil, "config", "init", dir)
	if r.code != 1 || !strings.Contains(r.stderr, "database.yaml") {
		t.Fatalf("%+v", r)
	}
	if read(t, mine) != "mine\n" {
		t.Fatal("existing file changed")
	}
	if _, err := os.Stat(filepath.Join(dir, "server.yaml")); err == nil {
		t.Fatal("init wrote files although one exists")
	}
}

// Covers: FR-20 (part)
// Acceptance: CLI commands (part)
func TestUsageErrorsExitTwo(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"config"}, {"config", "nope"}, {"config", "init"}, {"config", "init", "a", "b"},
		{"config", "check"}, {"config", "check", "a", "b"},
		{"keys"}, {"keys", "nope"}, {"keys", "generate"}, {"keys", "generate", "a", "b"},
		{"keys", "generate", "--type", "dsa", filepath.Join(dir, "k")},
		{"keys", "generate", "--bits", "1024", filepath.Join(dir, "k")},
		{"keys", "generate", "--bits", "x", filepath.Join(dir, "k")},
		{"keys", "generate", "--type", "ec", "--bits", "2048", filepath.Join(dir, "k")},
		{"keys", "generate", "--type", "encryption", "--bits", "2048", filepath.Join(dir, "k")},
		{"keys", "generate", "--bogus", filepath.Join(dir, "k")},
		{"healthcheck", "extra"}, {"version", "extra"},
	} {
		r := exec(t, nil, args...)
		if r.code != 2 || r.stderr == "" || r.stdout != "" {
			t.Errorf("%q: %+v", args, r)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a usage error wrote files: %v", entries)
	}
}

// Covers: FR-20 (part), SEC-09 (part)
// Acceptance: CLI commands (part)
// Acceptance: Secret file permissions and key sizes (part)
func TestKeysGenerateRSAAndEC(t *testing.T) {
	dir := t.TempDir()
	parse := func(file string) any {
		t.Helper()
		block, _ := pem.Decode([]byte(read(t, file)))
		if block == nil {
			t.Fatalf("%s is not PEM", file)
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	tests := []struct {
		name string
		args []string
		ok   func(any) bool
	}{
		{"default is RSA 2048", nil, func(k any) bool { r, ok := k.(*rsa.PrivateKey); return ok && r.N.BitLen() == 2048 }},
		{"rsa", []string{"--type", "rsa"}, func(k any) bool { r, ok := k.(*rsa.PrivateKey); return ok && r.N.BitLen() == 2048 }},
		{"rsa with bits", []string{"--type", "rsa", "--bits", "3072"}, func(k any) bool { r, ok := k.(*rsa.PrivateKey); return ok && r.N.BitLen() == 3072 }},
		{"ec", []string{"--type", "ec"}, func(k any) bool { e, ok := k.(*ecdsa.PrivateKey); return ok && e.Curve == elliptic.P256() }},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(dir, "sub", string(rune('a'+i))+".pem")
			r := exec(t, nil, append(append([]string{"keys", "generate"}, tc.args...), file)...)
			if r.code != 0 || !strings.Contains(r.stdout, file) {
				t.Fatalf("%+v", r)
			}
			if m := mode(t, file); m != 0o600 {
				t.Errorf("mode %04o, want 0600", m)
			}
			if !tc.ok(parse(file)) {
				t.Error("wrong key type or size")
			}
		})
	}
}

// Covers: FR-20 (part), SEC-09 (part)
// Acceptance: CLI commands (part)
// Acceptance: Secret file permissions and key sizes (part)
func TestKeysGenerateEncryptionKey(t *testing.T) {
	file := filepath.Join(t.TempDir(), "encryption_key")
	r := exec(t, nil, "keys", "generate", "--type", "encryption", file)
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if m := mode(t, file); m != 0o600 {
		t.Errorf("mode %04o", m)
	}
	text := read(t, file)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != 32 || len(strings.TrimSpace(text)) != 44 {
		t.Fatalf("not 32 random bytes as base64: %q, %v", text, err)
	}
	// The file is accepted by the loader: a valid directory using it.
	dir := initDir(t)
	other := filepath.Join(dir, "secrets/encryption_key")
	if r := exec(t, nil, "keys", "generate", "--type", "encryption", other); r.code != 0 {
		t.Fatal(r)
	}
	if r := exec(t, nil, "config", "check", dir); r.code != 0 {
		t.Fatalf("%+v", r)
	}
}

// Covers: FR-20 (part), SEC-09 (part)
// Acceptance: CLI commands (part)
func TestKeysGenerateRefusesToOverwrite(t *testing.T) {
	file := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(file, []byte("keep\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"rsa", "ec", "encryption"} {
		r := exec(t, nil, "keys", "generate", "--type", typ, file)
		if r.code != 1 || r.stderr == "" || r.stdout != "" {
			t.Fatalf("%s: %+v", typ, r)
		}
	}
	if read(t, file) != "keep\n" || mode(t, file) != 0o640 {
		t.Fatal("existing file changed")
	}
}

// Covers: FR-20 (part)
// Acceptance: CLI commands (part)
func TestConfigCheckOnAValidDirectory(t *testing.T) {
	r := exec(t, nil, "config", "check", initDir(t))
	if r.code != 0 || r.stderr != "" || strings.TrimSpace(r.stdout) != "ok" {
		t.Fatalf("%+v", r)
	}
}

// Covers: FR-20 (part), FR-19 (part)
// Acceptance: CLI commands (part)
func TestConfigCheckPrintsFileLineFieldAndExitsOne(t *testing.T) {
	dir := initDir(t)
	p := filepath.Join(dir, "realms/example.yaml")
	y := strings.Replace(read(t, p), "\nenabled: true\n", "\nenabeld: true\n", 1)
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	line := 1 + strings.Count(y[:strings.Index(y, "\nenabeld")], "\n") + 1
	r := exec(t, nil, "config", "check", dir)
	want := "realms/example.yaml:" + strconv.Itoa(line) + ": error: enabeld: "
	if r.code != 1 || !strings.Contains(r.stdout, want) {
		t.Fatalf("want %q in %+v", want, r)
	}
}

// Covers: FR-20 (part), FR-32 (part)
// Acceptance: CLI commands (part)
// Acceptance: Config validation (part)
func TestConfigCheckAcceptsTheTwoZeroLifetimes(t *testing.T) {
	dir := initDir(t)
	p := filepath.Join(dir, "realms/example.yaml")
	y := read(t, p)
	y = strings.Replace(y, "session_max_lifetime: 2160h", "session_max_lifetime: 0", 1)
	y = strings.Replace(y, "refresh_reuse_grace: 30s", "refresh_reuse_grace: 0", 1)
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := exec(t, nil, "config", "check", dir); r.code != 0 || strings.TrimSpace(r.stdout) != "ok" {
		t.Fatalf("%+v", r)
	}
}

// Covers: FR-20 (part), FR-30
// Acceptance: CLI commands (part)
// Acceptance: Reserved realm names
func TestConfigCheckRejectsReservedRealmNames(t *testing.T) {
	for _, name := range []string{"admin", "healthz", "readyz"} {
		dir := initDir(t)
		y := strings.Replace(read(t, filepath.Join(dir, "realms/example.yaml")), "name: example", "name: "+name, 1)
		if err := os.WriteFile(filepath.Join(dir, "realms", name+".yaml"), []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
		r := exec(t, nil, "config", "check", dir)
		want := "realms/" + name + ".yaml:"
		if r.code != 1 || !strings.Contains(r.stdout, want) || !strings.Contains(r.stdout, name+`" is reserved`) {
			t.Fatalf("%s: %+v", name, r)
		}
		// The other realm is unaffected: every diagnostic is about the reserved one.
		for _, l := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
			if !strings.HasPrefix(l, want) {
				t.Errorf("%s: a diagnostic about another file: %q", name, l)
			}
		}
	}
}

// Covers: FR-20 (part), SEC-09 (part)
// Acceptance: CLI commands (part)
// Acceptance: Secret file permissions and key sizes
func TestConfigCheckSecretFilePermissionsAndKeySizes(t *testing.T) {
	dir := initDir(t)
	key := filepath.Join(dir, "secrets/example/signing-2026-10.pem")
	srv := filepath.Join(dir, "server.yaml")
	y := strings.Replace(read(t, srv), "strict_permissions: true", "strict_permissions: false", 1)
	if err := os.WriteFile(srv, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	r := exec(t, nil, "config", "check", dir)
	if r.code != 0 || !strings.Contains(r.stdout, "warning") || !strings.Contains(r.stdout, "0644") {
		t.Fatalf("0644: %+v", r)
	}

	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := exec(t, nil, "config", "check", dir); r.code != 0 || strings.TrimSpace(r.stdout) != "ok" {
		t.Fatalf("0600: %+v", r)
	}

	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	y = strings.Replace(read(t, srv), "strict_permissions: false", "strict_permissions: true", 1)
	if err := os.WriteFile(srv, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := exec(t, nil, "config", "check", dir); r.code != 1 || !strings.Contains(r.stdout, "error") {
		t.Fatalf("strict: %+v", r)
	}

	// The key sizes the CLI writes: RSA 2048, EC P-256, and a larger RSA key.
	for _, k := range []struct {
		args []string
		ok   func(any) bool
	}{
		{[]string{"--type", "rsa"}, func(k any) bool { r, ok := k.(*rsa.PrivateKey); return ok && r.N.BitLen() == 2048 }},
		{[]string{"--type", "ec"}, func(k any) bool { e, ok := k.(*ecdsa.PrivateKey); return ok && e.Curve == elliptic.P256() }},
		{[]string{"--type", "rsa", "--bits", "3072"}, func(k any) bool { r, ok := k.(*rsa.PrivateKey); return ok && r.N.BitLen() == 3072 }},
	} {
		file := filepath.Join(dir, "secrets", strings.Join(k.args, "")+".pem")
		if r := exec(t, nil, append(append([]string{"keys", "generate"}, k.args...), file)...); r.code != 0 {
			t.Fatalf("%v: %+v", k.args, r)
		}
		block, _ := pem.Decode([]byte(read(t, file)))
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil || !k.ok(key) {
			t.Errorf("%v: wrong key (%v)", k.args, err)
		}
	}
}

// Covers: FR-20 (part)
// Acceptance: CLI commands (part)
func TestConfigCheckOnAnEmptyDirectoryExitsOne(t *testing.T) {
	if r := exec(t, nil, "config", "check", t.TempDir()); r.code != 1 || r.stdout == "" {
		t.Fatalf("%+v", r)
	}
}

func readyz(status int, seen *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = r.URL.Path
		}
		w.WriteHeader(status)
	})
}

// Covers: FR-20 (part), FR-16 (part)
// Acceptance: CLI commands (part)
func TestHealthcheckCallsReadyz(t *testing.T) {
	var path string
	srv := httptest.NewServer(readyz(http.StatusOK, &path))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if r := exec(t, map[string]string{"FEATHERAUTH_LISTEN": addr}, "healthcheck"); r.code != 0 || path != "/readyz" {
		t.Fatalf("%+v path %q", r, path)
	}
	// A listen address with no host reaches the loopback interface.
	_, port, _ := net.SplitHostPort(addr)
	if r := exec(t, map[string]string{"FEATHERAUTH_LISTEN": ":" + port}, "healthcheck"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
}

// Covers: FR-20 (part), FR-16 (part)
// Acceptance: CLI commands (part)
func TestHealthcheckFailures(t *testing.T) {
	bad := httptest.NewServer(readyz(http.StatusServiceUnavailable, nil))
	defer bad.Close()
	if r := exec(t, map[string]string{"FEATHERAUTH_LISTEN": strings.TrimPrefix(bad.URL, "http://")}, "healthcheck"); r.code != 1 || r.stderr == "" {
		t.Fatalf("503: %+v", r)
	}
	gone := httptest.NewServer(readyz(200, nil))
	addr := strings.TrimPrefix(gone.URL, "http://")
	gone.Close()
	if r := exec(t, map[string]string{"FEATHERAUTH_LISTEN": addr}, "healthcheck"); r.code != 1 {
		t.Fatalf("closed: %+v", r)
	}
}

// Covers: FR-20 (part), FR-16 (part)
// Acceptance: CLI commands (part)
func TestHealthcheckTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	var out, errb bytes.Buffer
	a := &app{stdout: &out, stderr: &errb, clock: clock.Real(), healthTimeout: 50 * time.Millisecond,
		getenv: func(k string) string {
			if k == "FEATHERAUTH_LISTEN" {
				return strings.TrimPrefix(srv.URL, "http://")
			}
			return ""
		}}
	if code := a.run(context.Background(), []string{"healthcheck"}); code != 1 || errb.Len() == 0 {
		t.Fatalf("code %d stderr %q", code, errb.String())
	}
}

// Covers: FR-20 (part), FR-17 (part)
// Acceptance: CLI commands (part)
func TestHealthcheckTakesTheAddressFromServerYaml(t *testing.T) {
	srv := httptest.NewServer(readyz(http.StatusOK, nil))
	defer srv.Close()
	dir := t.TempDir()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if err := os.WriteFile(filepath.Join(dir, "server.yaml"), []byte("public_url: https://a.example\nlisten: \""+addr+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := exec(t, map[string]string{"FEATHERAUTH_CONFIG_DIR": dir}, "healthcheck"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	// The environment overrides the file; an unreadable file is a failure.
	if r := exec(t, map[string]string{"FEATHERAUTH_CONFIG_DIR": filepath.Join(dir, "none")}, "healthcheck"); r.code != 1 {
		t.Fatalf("no server.yaml: %+v", r)
	}
}

// With the sqlite driver a named Postgres password file is not read, so the
// shipped example checks clean without it.
//
// Covers: FR-20 (part)
// Acceptance: CLI commands (part)
func TestConfigCheckIgnoresThePostgresPasswordFileWithSqlite(t *testing.T) {
	dir := initDir(t)
	p := filepath.Join(dir, "database.yaml")
	y := read(t, p)
	if !strings.Contains(y, "password_file: secrets/postgres_password") {
		t.Fatal("the example no longer names a password file")
	}
	if r := exec(t, nil, "config", "check", dir); r.code != 0 || strings.TrimSpace(r.stdout) != "ok" {
		t.Fatalf("%+v", r)
	}
	// With the postgres driver the same missing file is an error.
	y = strings.Replace(y, "driver: sqlite", "driver: postgres", 1)
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := exec(t, nil, "config", "check", dir); r.code != 1 || !strings.Contains(r.stdout, "database.yaml:") || !strings.Contains(r.stdout, "postgres.password_file") {
		t.Fatalf("%+v", r)
	}
}

// Covers: SEC-30
// Acceptance: Client secret length
func TestConfigCheckWarnsOnAShortClientSecretAndExitsZero(t *testing.T) {
	const block = "  api:\n    type: confidential\n    client_secret_file: secrets/example/api_secret\n    redirect_uris: [https://api.example.com/callback]\n"
	tests := []struct {
		name  string
		chars int
		warn  bool
	}{
		{"31 characters", 31, true},
		{"32 characters", 32, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := initDir(t)
			p := filepath.Join(dir, "realms/example.yaml")
			y := read(t, p) + block
			if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
				t.Fatal(err)
			}
			secret := "SENTINEL-" + strings.Repeat("z", tt.chars-len("SENTINEL-"))
			if err := os.WriteFile(filepath.Join(dir, "secrets/example/api_secret"), []byte(secret+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			r := exec(t, nil, "config", "check", dir)
			if r.code != 0 || r.stderr != "" {
				t.Fatalf("%+v", r)
			}
			if strings.Contains(r.stdout, secret) {
				t.Fatal("the secret reached the output")
			}
			if !tt.warn {
				if strings.TrimSpace(r.stdout) != "ok" {
					t.Fatalf("stdout %q", r.stdout)
				}
				return
			}
			line := strings.Count(y[:strings.Index(y, "    client_secret_file: secrets/example/api_secret")], "\n") + 1
			want := "realms/example.yaml:" + strconv.Itoa(line) + ": warning: clients.api.client_secret_file: " +
				"secret file secrets/example/api_secret is shorter than 32 characters; use a client secret of at least 32 characters\n"
			if r.stdout != want {
				t.Fatalf("stdout %q, want %q", r.stdout, want)
			}
		})
	}
}
