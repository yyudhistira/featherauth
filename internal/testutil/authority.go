package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/secure"
)

// The validity of every test certificate: far enough in both directions that
// no test depends on the real date.
var (
	certNotBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	certNotAfter  = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Authority is a certificate authority of a test, with a fresh EC key. PEM is
// the content of the file a root_cert_file option names. The key is a test
// key, never a real one.
type Authority struct {
	PEM  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewAuthority returns a new test certificate authority.
func NewAuthority(t testing.TB) *Authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          testSerial(t),
		Subject:               pkix.Name{CommonName: "featherauth test authority"},
		NotBefore:             certNotBefore,
		NotAfter:              certNotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(secure.Default, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Authority{PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert: cert, key: key}
}

// ServerCertificate returns a TLS certificate for a server, signed by the
// authority. Each host is a DNS name, or an IP address that goes in the IP
// SAN; the first one is the common name.
func (a *Authority) ServerCertificate(t testing.TB, hosts ...string) tls.Certificate {
	t.Helper()
	if len(hosts) == 0 {
		t.Fatal("ServerCertificate needs a host")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: testSerial(t),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    certNotBefore,
		NotAfter:     certNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(secure.Default, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// testSerial returns a random certificate serial number.
func testSerial(t testing.TB) *big.Int {
	t.Helper()
	buf := make([]byte, 16)
	if _, err := io.ReadFull(secure.Default, buf); err != nil {
		t.Fatal(err)
	}
	return new(big.Int).SetBytes(buf)
}
