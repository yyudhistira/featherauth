// Package tlscert makes self-signed certificates and their keys for tests. The
// keys are fresh test fixtures, never real ones. It is a package of its own, so
// that the configuration tests can use it without importing internal/testutil,
// which imports the configuration.
package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// Pair is a certificate with its key, both in PEM.
type Pair struct {
	CertPEM []byte
	KeyPEM  []byte
	// Leaf is the parsed certificate, for its serial number and names.
	Leaf *x509.Certificate
}

// New makes a self-signed EC P-256 certificate for names. A name that parses
// as an IP address is an IP subject alternative name, any other a DNS name.
func New(t testing.TB, names ...string) Pair {
	t.Helper()
	if len(names) == 0 {
		t.Fatal("tlscert.New needs at least one name")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	serial := make([]byte, 16)
	if _, err := io.ReadFull(secure.Default, serial); err != nil {
		t.Fatal(err)
	}
	serial[0] &= 0x7f // a positive serial number
	now := clock.Real().Now()
	tmpl := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serial),
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(secure.Default, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Pair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Leaf:    leaf,
	}
}
