package token_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/token"
)

const esRealm = `name: main
tokens:
  algorithm: ES256
keys:
  - { kid: rsa-new, file: secrets/rsa-new.pem, state: active }
  - { kid: rsa-old, file: secrets/rsa-old.pem, state: verify_only }
  - { kid: ec-new, file: secrets/ec-new.pem, state: active }
  - { kid: ec-old, file: secrets/ec-old.pem, state: verify_only }
providers:
  google:
    enabled: true
    client_id: 1234.apps.googleusercontent.com
    client_secret_file: secrets/google_secret
clients:
  web:
    redirect_uris: [https://app.example.com/callback]
`

func loadRealm(t *testing.T) (*config.Realm, config.Secrets) {
	t.Helper()
	d := configdir.New(t)
	d.Server(t, "public_url: https://auth.example.com\n")
	d.Realm(t, "main", esRealm)
	for _, f := range []string{"rsa-new", "rsa-old"} {
		d.RSAKey(t, "secrets/"+f+".pem")
	}
	for _, f := range []string{"ec-new", "ec-old"} {
		d.AppleKey(t, "secrets/"+f+".pem")
	}
	d.Secret(t, "secrets/google_secret")
	l, err := config.NewLoader(d.Root, clock.NewFake(time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	snap := l.Current()
	r, ok := snap.Realm("main")
	if !ok {
		t.Fatal("no realm main")
	}
	return r, snap.Secrets()
}

// Covers: FR-10 (part), SEC-07 (part)
// Acceptance: JWKS content (part)
func TestJWKSKeysCarryUseAlgKidAndNoPrivateMember(t *testing.T) {
	r, s := loadRealm(t)
	ks, err := token.NewKeySet(r, s)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(ks.JWKS(), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"rsa-new": "RS256", "rsa-old": "RS256", "ec-new": "ES256", "ec-old": "ES256"}
	if len(doc.Keys) != len(want) {
		t.Fatalf("got %d keys, want %d", len(doc.Keys), len(want))
	}
	for _, k := range doc.Keys {
		kid, _ := k["kid"].(string)
		alg, ok := want[kid]
		if !ok {
			t.Fatalf("unexpected kid %q", kid)
		}
		delete(want, kid)
		if k["use"] != "sig" || k["alg"] != alg {
			t.Errorf("%s: use=%v alg=%v, want sig %s", kid, k["use"], k["alg"], alg)
		}
		for _, priv := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, has := k[priv]; has {
				t.Errorf("%s: private member %q published", kid, priv)
			}
		}
		pub, a, ok := ks.Lookup(kid)
		if !ok || a != alg {
			t.Errorf("Lookup(%s) = %v, %q, %v", kid, pub, a, ok)
		}
		b64 := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.Bytes()) }
		switch p := pub.(type) {
		case *rsa.PublicKey:
			e := big.NewInt(int64(p.E))
			if k["kty"] != "RSA" || k["n"] != b64(p.N) || k["e"] != b64(e) {
				t.Errorf("%s: RSA members %v do not match the looked-up key", kid, k)
			}
			if _, has := k["crv"]; has {
				t.Errorf("%s: RSA key has crv", kid)
			}
		case *ecdsa.PublicKey:
			raw, err := p.Bytes() // 0x04 || X || Y
			if err != nil || len(raw) != 65 {
				t.Fatalf("%s: public key bytes: %v", kid, err)
			}
			if k["kty"] != "EC" || k["crv"] != "P-256" ||
				k["x"] != base64.RawURLEncoding.EncodeToString(raw[1:33]) ||
				k["y"] != base64.RawURLEncoding.EncodeToString(raw[33:]) {
				t.Errorf("%s: EC members %v do not match the looked-up key", kid, k)
			}
		default:
			t.Errorf("%s: unexpected key type %T", kid, pub)
		}
	}
	if _, _, ok := ks.Lookup("nope"); ok {
		t.Error("Lookup of an unknown kid succeeded")
	}
}

// Covers: SEC-07 (part)
func TestNewKeySetFailsWhenKidHasNoLoadedKey(t *testing.T) {
	r, s := loadRealm(t)
	r2 := *r
	r2.Keys = append(append([]config.Key(nil), r.Keys...), config.Key{Kid: "ghost", File: "x", State: "verify_only"})
	if _, err := token.NewKeySet(&r2, s); err == nil {
		t.Fatal("want an error for a kid without a loaded key")
	}
}

// Covers: SEC-09 (part)
// Acceptance: Secret file permissions and key sizes (part)
func TestGenerateRSA(t *testing.T) {
	for _, bits := range []int{2048, 3072} {
		b, err := token.GenerateRSA(bits)
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			t.Fatal("not PEM")
		}
		k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if k.N.BitLen() != bits {
			t.Errorf("got %d bits, want %d", k.N.BitLen(), bits)
		}
	}
	if _, err := token.GenerateRSA(1024); err == nil {
		t.Error("1024-bit RSA key accepted")
	}
}

// Covers: SEC-09 (part)
// Acceptance: Secret file permissions and key sizes (part)
func TestGenerateECIsP256(t *testing.T) {
	b, err := token.GenerateEC()
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatal("not PEM")
	}
	k, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if k.Curve != elliptic.P256() {
		t.Error("not P-256")
	}
}

// Covers: SEC-09 (part)
// Acceptance: Secret file permissions and key sizes (part)
func TestGenerateEncryptionKeyIs32Bytes(t *testing.T) {
	s, err := token.GenerateEncryptionKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 || len(s) != 44 {
		t.Fatalf("got %d chars, %d bytes, err %v", len(s), len(b), err)
	}
	s2, _ := token.GenerateEncryptionKey()
	if s == s2 {
		t.Error("two keys are equal")
	}
}

// Covers: SEC-09 (part)
// Acceptance: Secret file permissions and key sizes (part)
func TestWriteKeyFileMode0600UnderPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	p := filepath.Join(t.TempDir(), "k.pem")
	if err := token.WriteKeyFile(p, []byte("data")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(p); string(b) != "data" {
		t.Errorf("content %q", b)
	}
}

func TestWriteKeyFileRefusesToOverwrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(p, []byte("sentinel"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := token.WriteKeyFile(p, []byte("new")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("err = %v, want os.ErrExist", err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "sentinel" || fi.Mode().Perm() != 0o644 {
		t.Errorf("file changed: %q, %v", b, fi.Mode().Perm())
	}
}

func TestWriteKeyFileReportsErrors(t *testing.T) {
	err := token.WriteKeyFile(filepath.Join(t.TempDir(), "missing", "k.pem"), []byte("x"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want os.ErrNotExist", err)
	}
}

// Covers: SEC-09 (part)
// Acceptance: Secret file permissions and key sizes (part)
func TestGeneratedKeyFilesAreAcceptedByTheLoader(t *testing.T) {
	d := configdir.New(t)
	d.Server(t, "public_url: https://auth.example.com\n")
	d.Realm(t, "main", `name: main
keys:
  - { kid: gen-rsa, file: gen-rsa.pem, state: active }
  - { kid: gen-ec, file: gen-ec.pem, state: verify_only }
providers:
  google:
    enabled: true
    client_id: 1234.apps.googleusercontent.com
    client_secret_file: google_secret
clients:
  web:
    redirect_uris: [https://app.example.com/callback]
`)
	d.Secret(t, "google_secret")
	rsaPEM, err := token.GenerateRSA(2048)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM, err := token.GenerateEC()
	if err != nil {
		t.Fatal(err)
	}
	if err := token.WriteKeyFile(filepath.Join(d.Root, "gen-rsa.pem"), rsaPEM); err != nil {
		t.Fatal(err)
	}
	if err := token.WriteKeyFile(filepath.Join(d.Root, "gen-ec.pem"), ecPEM); err != nil {
		t.Fatal(err)
	}
	l, err := config.NewLoader(d.Root, clock.NewFake(time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)), nil)
	if err != nil {
		t.Fatalf("the loader rejected generated keys: %v", err)
	}
	for _, kid := range []string{"gen-rsa", "gen-ec"} {
		if l.Current().Secrets().Signing(kid) == nil {
			t.Errorf("key %s was not loaded", kid)
		}
	}
	r, _ := l.Current().Realm("main")
	if _, err := token.NewKeySet(r, l.Current().Secrets()); err != nil {
		t.Fatal(err)
	}
}
