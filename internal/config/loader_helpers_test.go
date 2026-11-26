package config_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
)

var testStart = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

var (
	keyOnce  sync.Once
	rsaBytes []byte
	ecBytes  []byte
)

func testKeys(t testing.TB) (rsaPEM, ecPEM []byte) {
	t.Helper()
	keyOnce.Do(func() {
		rk, err := rsa.GenerateKey(secure.Default, 2048)
		if err != nil {
			panic(err)
		}
		rsaBytes = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})
		ek, err := ecdsa.GenerateKey(elliptic.P256(), secure.Default)
		if err != nil {
			panic(err)
		}
		der, err := x509.MarshalECPrivateKey(ek)
		if err != nil {
			panic(err)
		}
		ecBytes = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	})
	return rsaBytes, ecBytes
}

// cfgDir is a configuration directory in a temporary directory.
type cfgDir struct {
	t    testing.TB
	root string
}

func newCfgDir(t testing.TB) *cfgDir {
	t.Helper()
	d := &cfgDir{t: t, root: t.TempDir()}
	d.write("server.yaml", "public_url: https://auth.example.com\n", 0o600)
	return d
}

func (d *cfgDir) write(name, content string, mode os.FileMode) {
	d.t.Helper()
	p := filepath.Join(d.root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		d.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		d.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		d.t.Fatal(err)
	}
}

func (d *cfgDir) remove(name string) {
	d.t.Helper()
	if err := os.Remove(filepath.Join(d.root, name)); err != nil {
		d.t.Fatal(err)
	}
}

// realm writes a valid realm file and its signing key; extra is appended
// to the realm file.
func (d *cfgDir) realm(name, display, extra string) {
	d.t.Helper()
	d.realmKid(name, name+"-k1", display, extra)
}

func (d *cfgDir) realmKid(name, kid, display, extra string) {
	d.t.Helper()
	rsaPEM, _ := testKeys(d.t)
	d.write("secrets/"+name+"/signing.pem", string(rsaPEM), 0o600)
	d.write("realms/"+name+".yaml", fmt.Sprintf(`name: %s
display_name: %s
keys:
  - { kid: %s, file: secrets/%s/signing.pem, state: active }
clients:
  web:
    redirect_uris: [https://app.example.com/cb]
%s`, name, display, kid, name, extra), 0o600)
}

func (d *cfgDir) loader(t testing.TB) (*config.Loader, *clock.Fake, *bytes.Buffer) {
	t.Helper()
	clk := clock.NewFake(testStart)
	var buf bytes.Buffer
	l, err := config.NewLoader(d.root, clk, logx.New(&syncWriter{w: &buf}, slog.LevelDebug, clk))
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	return l, clk, &buf
}

// syncWriter makes a buffer safe for the loader's goroutines.
type syncWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func errorsOf(ds []config.Diagnostic) []config.Diagnostic {
	var out []config.Diagnostic
	for _, d := range ds {
		if d.Severity == config.Error {
			out = append(out, d)
		}
	}
	return out
}

func hasDiag(ds []config.Diagnostic, file string, sev config.Severity, field string) bool {
	for _, d := range ds {
		if d.File == file && d.Severity == sev && (field == "" || d.Field == field) {
			return true
		}
	}
	return false
}

func newFake() *clock.Fake { return clock.NewFake(testStart) }
