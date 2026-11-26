package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/yyudhistira/featherauth/internal/secure"
)

// ECKey generates an EC P-256 key and returns it with its PKCS 8 PEM, the
// format of an Apple .p8 file. It is a fresh test key, never a real one.
func ECKey(t testing.TB) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	return ECKeyOn(t, elliptic.P256())
}

// ECKeyOn is ECKey on another curve.
func ECKeyOn(t testing.TB, curve elliptic.Curve) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// RSAKeyPEM generates an RSA key and returns its PKCS 8 PEM.
func RSAKeyPEM(t testing.TB) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(secure.Default, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
