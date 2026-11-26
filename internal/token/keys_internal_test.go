package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// stubSecrets returns a fixed signer per kid; it is a config.Secrets for
// feeding NewKeySet key types the loader would already have rejected.
type stubSecrets map[string]crypto.Signer

func (stubSecrets) LogValue() slog.Value                                  { return slog.Value{} }
func (s stubSecrets) Signing(kid string) crypto.Signer                    { return s[kid] }
func (stubSecrets) AppleKey(string, string) *ecdsa.PrivateKey             { return nil }
func (stubSecrets) ClientSecret(string, config.SecretKind, string) string { return "" }
func (stubSecrets) EncryptionKeys() [][]byte                              { return nil }

type badPub struct{}

func (badPub) Public() crypto.PublicKey { return struct{}{} }
func (badPub) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestNewKeySetRejectsBadInput(t *testing.T) {
	rsa1024, err := rsa.GenerateKey(secure.Default, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	ec256, err := ecdsa.GenerateKey(elliptic.P256(), secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, _ := ed25519.GenerateKey(secure.Default)
	one := &config.Realm{Name: "main", Keys: []config.Key{{Kid: "k", State: "active"}}}
	twice := &config.Realm{Name: "main", Keys: []config.Key{{Kid: "k", State: "active"}, {Kid: "k", State: "verify_only"}}}
	for _, tt := range []struct {
		name string
		r    *config.Realm
		s    config.Secrets
		want string
	}{
		{"nil realm", nil, stubSecrets{}, "token: a realm and its secrets are required"},
		{"nil secrets", one, nil, "token: a realm and its secrets are required"},
		{"no loaded key", one, stubSecrets{}, `token: realm main: key "k" has no loaded key`},
		{"RSA 1024", one, stubSecrets{"k": rsa1024}, `token: realm main: key "k": an RSA key must have at least 2048 bits, got 1024`},
		{"EC P-384", one, stubSecrets{"k": ec384}, `token: realm main: key "k": an EC key must use curve P-256`},
		{"ed25519", one, stubSecrets{"k": ed}, `token: realm main: key "k": the key must be RSA or EC P-256`},
		{"unknown public type", one, stubSecrets{"k": badPub{}}, `token: realm main: key "k": the key must be RSA or EC P-256`},
		{"duplicate kid", twice, stubSecrets{"k": ec256}, `token: realm main: kid "k" is used twice`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ks, err := NewKeySet(tt.r, tt.s)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if ks != nil {
				t.Error("a key set was returned with the error")
			}
		})
	}
}

// swap replaces a seam for one test and restores it afterwards. Tests that
// use it must not run in parallel.
func swap[T any](t *testing.T, seam *T, v T) {
	t.Helper()
	old := *seam
	*seam = v
	t.Cleanup(func() { *seam = old })
}

func TestSeamErrorsAreReturned(t *testing.T) {
	boom := errors.New("boom")
	ec256, err := ecdsa.GenerateKey(elliptic.P256(), secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	one := &config.Realm{Name: "main", Keys: []config.Key{{Kid: "k", State: "active"}}}
	sec := stubSecrets{"k": ec256}
	t.Run("jwk import", func(t *testing.T) {
		swap(t, &jwkImport, func(any) (jwk.Key, error) { return nil, boom })
		if _, err := NewKeySet(one, sec); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
	})
	t.Run("jwk set", func(t *testing.T) {
		swap(t, &jwkSet, func(jwk.Key, string, any) error { return boom })
		if _, err := NewKeySet(one, sec); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
	})
	t.Run("marshal jwks", func(t *testing.T) {
		swap(t, &marshalJWKS, func(any) ([]byte, error) { return nil, boom })
		if _, err := NewKeySet(one, sec); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
	})
	t.Run("generate rsa", func(t *testing.T) {
		swap(t, &generateRSAKey, func(int) (*rsa.PrivateKey, error) { return nil, boom })
		if _, err := GenerateRSA(2048); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
	})
	t.Run("generate ec", func(t *testing.T) {
		swap(t, &generateECKey, func() (*ecdsa.PrivateKey, error) { return nil, boom })
		if _, err := GenerateEC(); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
	})
	t.Run("marshal ec", func(t *testing.T) {
		swap(t, &marshalECKey, func(*ecdsa.PrivateKey) ([]byte, error) { return nil, boom })
		if _, err := GenerateEC(); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
	})
	t.Run("random read", func(t *testing.T) {
		swap(t, &randRead, func([]byte) (int, error) { return 0, boom })
		if _, err := GenerateEncryptionKey(); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want boom", err)
		}
	})
}

type brokenFile struct {
	chmod, write, close error
	closed              bool
}

func (f *brokenFile) Chmod(os.FileMode) error     { return f.chmod }
func (f *brokenFile) Write(b []byte) (int, error) { return len(b), f.write }
func (f *brokenFile) Close() error                { f.closed = true; return f.close }

func TestWriteKeyFileFailuresRemoveThePartialFile(t *testing.T) {
	boom := errors.New("boom")
	for _, tt := range []struct {
		name string
		f    *brokenFile
	}{
		{"chmod", &brokenFile{chmod: boom}},
		{"write", &brokenFile{write: boom}},
		{"close", &brokenFile{close: boom}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "k.pem")
			if err := os.WriteFile(p, []byte("partial"), 0o600); err != nil {
				t.Fatal(err)
			}
			swap(t, &openNewFile, func(string) (newFile, error) { return tt.f, nil })
			if err := WriteKeyFile(p, []byte("x")); !errors.Is(err, boom) {
				t.Fatalf("err = %v, want boom", err)
			}
			if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("partial file still there: %v", err)
			}
			if !tt.f.closed {
				t.Error("file not closed")
			}
		})
	}
}
