// Package configdir builds configuration directories in a temporary directory
// for tests: server and realm files, generated keys and secrets, all with
// mode 0600. It is test support and only tests may import it.
package configdir

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/yyudhistira/featherauth/internal/secure"
)

// Dir is a configuration directory.
type Dir struct {
	// Root is the directory to pass to the loader.
	Root string
}

// New returns an empty configuration directory in t.TempDir().
func New(t testing.TB) *Dir {
	t.Helper()
	return &Dir{Root: t.TempDir()}
}

// Write writes a file relative to the root with mode 0600, creating parent
// directories.
func (d *Dir) Write(t testing.TB, name, content string) {
	t.Helper()
	p := filepath.Join(d.Root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil { // not subject to the umask
		t.Fatal(err)
	}
}

// Server writes server.yaml.
func (d *Dir) Server(t testing.TB, yaml string) {
	t.Helper()
	d.Write(t, "server.yaml", yaml)
}

// Realm writes realms/<name>.yaml.
func (d *Dir) Realm(t testing.TB, name, yaml string) {
	t.Helper()
	d.Write(t, "realms/"+name+".yaml", yaml)
}

var (
	rsaOnce sync.Once
	rsaPEM  []byte
	ecOnce  sync.Once
	ecPEM   []byte
)

// RSAKey writes an RSA 2048 private key in PEM. The key is generated once per
// test binary and shared, which keeps tests fast.
func (d *Dir) RSAKey(t testing.TB, rel string) {
	t.Helper()
	rsaOnce.Do(func() {
		k, err := rsa.GenerateKey(secure.Default, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rsaPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	})
	d.Write(t, rel, string(rsaPEM))
}

// AppleKey writes an EC P-256 private key as PKCS 8 PEM, the .p8 format.
func (d *Dir) AppleKey(t testing.TB, rel string) {
	t.Helper()
	ecOnce.Do(func() {
		k, err := ecdsa.GenerateKey(elliptic.P256(), secure.Default)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		ecPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	})
	d.Write(t, rel, string(ecPEM))
}

// Secret writes a random text secret, such as a provider client secret.
func (d *Dir) Secret(t testing.TB, rel string) {
	t.Helper()
	s, err := secure.Token(secure.Default, 32)
	if err != nil {
		t.Fatal(err)
	}
	d.Write(t, rel, s+"\n")
}

// EncryptionKey writes a 32-byte random key as base64.
func (d *Dir) EncryptionKey(t testing.TB, rel string) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := io.ReadFull(secure.Default, b); err != nil {
		t.Fatal(err)
	}
	d.Write(t, rel, base64.StdEncoding.EncodeToString(b)+"\n")
}
