// Package token holds the signing keys, JWKS, claim encoding and token
// services of a realm.
package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
)

const (
	// DefaultRSABits is the RSA key size `keys generate` uses by default.
	DefaultRSABits = 2048
	// encryptionKeyLen is the size of an encryption key in bytes.
	encryptionKeyLen = 32
)

// Seams for the library calls whose errors cannot be provoked with real
// input; tests replace them (and restore them) to reach those branches.
var (
	jwkImport      = func(k any) (jwk.Key, error) { return jwk.Import(k) }
	jwkSet         = func(j jwk.Key, name string, v any) error { return j.Set(name, v) }
	marshalJWKS    = func(v any) ([]byte, error) { return json.Marshal(v) }
	generateRSAKey = func(bits int) (*rsa.PrivateKey, error) { return rsa.GenerateKey(secure.Default, bits) }
	generateECKey  = func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), secure.Default) }
	marshalECKey   = x509.MarshalECPrivateKey
	openNewFile    = func(path string) (newFile, error) {
		return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	}
	randRead = func(b []byte) (int, error) { return io.ReadFull(secure.Default, b) }
)

// newFile is the part of *os.File that WriteKeyFile uses.
type newFile interface {
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Close() error
}

type keyEntry struct {
	pub crypto.PublicKey
	alg string
}

// KeySet is the public side of a realm's signing keys: every active and
// verify-only key, published in the JWKS. It is immutable.
type KeySet struct {
	keys map[string]keyEntry
	jwks []byte
}

// NewKeySet builds the key set of a realm from the keys the loader read. Each
// entry of r.Keys must have a loaded key in s, with a kid used once; an RSA key
// needs at least 2048 bits and an EC key must be on P-256.
func NewKeySet(r *config.Realm, s config.Secrets) (*KeySet, error) {
	if r == nil || s == nil {
		return nil, errors.New("token: a realm and its secrets are required")
	}
	ks := &KeySet{keys: map[string]keyEntry{}}
	pubs := make([]jwk.Key, 0, len(r.Keys))
	for _, k := range r.Keys {
		if _, dup := ks.keys[k.Kid]; dup {
			return nil, fmt.Errorf("token: realm %s: kid %q is used twice", r.Name, k.Kid)
		}
		signer := s.Signing(k.Kid)
		if signer == nil {
			return nil, fmt.Errorf("token: realm %s: key %q has no loaded key", r.Name, k.Kid)
		}
		pub := signer.Public()
		alg, err := checkPublic(pub)
		if err != nil {
			return nil, fmt.Errorf("token: realm %s: key %q: %w", r.Name, k.Kid, err)
		}
		j, err := jwkImport(pub)
		if err != nil {
			return nil, fmt.Errorf("token: realm %s: key %q: %w", r.Name, k.Kid, err)
		}
		for name, v := range map[string]any{jwk.KeyIDKey: k.Kid, jwk.KeyUsageKey: "sig", jwk.AlgorithmKey: alg} {
			if err := jwkSet(j, name, v); err != nil {
				return nil, fmt.Errorf("token: realm %s: key %q: set %s: %w", r.Name, k.Kid, name, err)
			}
		}
		pubs = append(pubs, j)
		ks.keys[k.Kid] = keyEntry{pub: pub, alg: alg}
	}
	b, err := marshalJWKS(map[string][]jwk.Key{"keys": pubs})
	if err != nil {
		return nil, fmt.Errorf("token: realm %s: encode JWKS: %w", r.Name, err)
	}
	ks.jwks = b
	return ks, nil
}

// checkPublic returns the JWS algorithm of an acceptable public key.
func checkPublic(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < DefaultRSABits {
			return "", fmt.Errorf("an RSA key must have at least %d bits, got %d", DefaultRSABits, k.N.BitLen())
		}
		return "RS256", nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", errors.New("an EC key must use curve P-256")
		}
		return "ES256", nil
	}
	return "", errors.New("the key must be RSA or EC P-256")
}

// JWKS returns the JSON key set document. The caller must not modify it.
func (k *KeySet) JWKS() []byte { return k.jwks }

// Lookup returns the public key and the algorithm of a kid.
func (k *KeySet) Lookup(kid string) (crypto.PublicKey, string, bool) {
	e, ok := k.keys[kid]
	return e.pub, e.alg, ok
}

// GenerateRSA returns a new RSA private key as PEM. bits must be at least 2048.
func GenerateRSA(bits int) ([]byte, error) {
	if bits < DefaultRSABits {
		return nil, fmt.Errorf("an RSA key must have at least %d bits", DefaultRSABits)
	}
	k, err := generateRSAKey(bits)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), nil
}

// GenerateEC returns a new EC P-256 private key as PEM.
func GenerateEC() ([]byte, error) {
	k, err := generateECKey()
	if err != nil {
		return nil, err
	}
	der, err := marshalECKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// GenerateEncryptionKey returns 32 random bytes as base64 (44 characters).
func GenerateEncryptionKey() (string, error) {
	b := make([]byte, encryptionKeyLen)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// WriteKeyFile creates a key file with mode 0600, whatever the umask. It
// refuses to overwrite: an existing file is an error (os.ErrExist) and stays
// unchanged.
func WriteKeyFile(path string, data []byte) (err error) {
	f, err := openNewFile(path)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Close()
}
