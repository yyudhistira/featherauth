package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/testutil/tlscert"
)

// tlsSettings are the server.yaml options of built-in TLS in the tests: the
// loopback listener, the HTTPS and the redirect listeners on free ports, and
// the pair in the configuration directory.
const tlsSettings = "listen: \"127.0.0.1:8080\"\n" +
	"tls:\n  mode: files\n  listen: \"127.0.0.1:0\"\n  http_listen: \"127.0.0.1:0\"\n" +
	"  cert_file: secrets/tls_cert.pem\n  key_file: secrets/tls_key.pem\n"

// enableTLSFiles appends the built-in TLS settings to the server.yaml of e. The
// environment loads its configuration when it is made, so the pair the settings
// name is written after it, and the file is changed afterwards.
func enableTLSFiles(t *testing.T, e *server.Env) {
	t.Helper()
	editFile(t, filepath.Join(e.ConfigDir(), "server.yaml"), func(y string) string { return y + tlsSettings })
}

// writeTLSFile writes path with exactly mode (the umask does not apply).
func writeTLSFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// writeTLSPair writes the pair the settings name: the certificate, and the key
// with mode 0600, as strict_permissions requires.
func writeTLSPair(t *testing.T, dir string, p tlscert.Pair) {
	t.Helper()
	writeTLSFile(t, filepath.Join(dir, "secrets", "tls_cert.pem"), p.CertPEM, 0o644)
	writeTLSFile(t, filepath.Join(dir, "secrets", "tls_key.pem"), p.KeyPEM, 0o600)
}

// servedSerial returns the serial number of the certificate the HTTPS listener
// at addr serves, from a handshake of TLS 1.2 or newer. The chain is not
// verified here; the HTTPS request checks it.
func servedSerial(t *testing.T, addr string) *big.Int {
	t.Helper()
	d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("handshake with %s: %v", addr, err)
	}
	defer conn.Close()
	return conn.(*tls.Conn).ConnectionState().PeerCertificates[0].SerialNumber
}

// Covers: FR-52, SEC-41 (part)
// Acceptance: Built-in TLS with files (part)
//
// The service serves every endpoint over HTTPS with the pair of the files, and
// the same HTTPS listener refuses TLS 1.1. Plain HTTP on the redirect listener
// answers 301 to the URL under public_url, the loopback listener answers only
// the health endpoints, and a changed pair is served without a restart: after a
// file change, after SIGHUP, and a broken pair is logged while the previous one
// stays.
func TestServeBuiltInTLSFromFiles(t *testing.T) {
	e := server.New(t)
	first := tlscert.New(t, "auth.example.com", "127.0.0.1")
	writeTLSPair(t, e.ConfigDir(), first)
	enableTLSFiles(t, e)
	serviceConfigDir(t, e)
	s := startServiceIn(t, e, e.ConfigDir(), clock.Real())

	bound := s.boundAddrs()
	if len(bound) != 3 {
		t.Fatalf("listened on %v, want the loopback listener, HTTPS and the redirect", bound)
	}
	httpsAddr, redirectAddr := bound[1], bound[2]

	roots := x509.NewCertPool()
	roots.AddCert(first.Leaf)
	https := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true, TLSClientConfig: &tls.Config{
			RootCAs: roots, ServerName: "auth.example.com", MinVersion: tls.VersionTLS12,
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	get := func(c *http.Client, url string) (int, http.Header, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}

	// HTTPS serves the endpoints; the certificate is verified against its names.
	code, _, body := get(https, "https://"+httpsAddr+"/main/.well-known/openid-configuration")
	if code != http.StatusOK || !strings.Contains(body, `"https://auth.example.com/main"`) {
		t.Fatalf("HTTPS discovery: %d %s", code, body)
	}
	if got := servedSerial(t, httpsAddr); got.Cmp(first.Leaf.SerialNumber) != 0 {
		t.Fatal("HTTPS does not serve the certificate of the files")
	}
	// TLS 1.1 is refused; the TLS 1.2 handshake above is the positive control.
	d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11}}
	if conn, err := d.DialContext(t.Context(), "tcp", httpsAddr); err == nil {
		conn.Close()
		t.Fatal("the HTTPS listener accepted TLS 1.1")
	}

	// Plain HTTP on the redirect listener answers 301 to the URL under public_url.
	code, hdr, _ := get(s.http, "http://"+redirectAddr+"/main/authorize?client_id=web")
	if code != http.StatusMovedPermanently || hdr.Get("Location") != "https://auth.example.com/main/authorize?client_id=web" {
		t.Fatalf("redirect: %d, Location %q", code, hdr.Get("Location"))
	}
	if hdr.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("the redirect answer lacks nosniff")
	}

	// The loopback listener answers the health endpoints and 404 for the rest.
	if code, _ := s.get("/readyz"); code != http.StatusOK {
		t.Errorf("loopback /readyz: %d", code)
	}
	if code, _ := s.get("/main/authorize"); code != http.StatusNotFound {
		t.Errorf("loopback /main/authorize: %d, want 404", code)
	}
	if code, _ := s.get("/main/.well-known/openid-configuration"); code != http.StatusNotFound {
		t.Errorf("loopback discovery: %d, want 404", code)
	}

	// A changed pair is served after the debounce, without a restart.
	certPath := filepath.Join(e.ConfigDir(), "secrets", "tls_cert.pem")
	second := tlscert.New(t, "auth.example.com", "127.0.0.1")
	before := s.logs.count(`"certificate loaded"`)
	writeTLSPair(t, e.ConfigDir(), second)
	s.logs.waitFor(t, `"certificate loaded"`, before+1)
	if got := servedSerial(t, httpsAddr); got.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatal("the changed pair is not served after the file change")
	}

	// A broken pair is logged and the pair being served stays.
	before = s.logs.count(`"cannot load the certificate pair`)
	writeTLSFile(t, certPath, []byte("not a certificate\n"), 0o644)
	s.logs.waitFor(t, `"cannot load the certificate pair`, before+1)
	if got := servedSerial(t, httpsAddr); got.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatal("a broken pair replaced the pair being served")
	}

	// A valid pair again, then SIGHUP reloads the files as they are.
	third := tlscert.New(t, "auth.example.com", "127.0.0.1")
	before = s.logs.count(`"certificate loaded"`)
	writeTLSPair(t, e.ConfigDir(), third)
	s.logs.waitFor(t, `"certificate loaded"`, before+1)
	before = s.logs.count(`"certificate loaded"`)
	s.hup <- syscall.SIGHUP
	s.logs.waitFor(t, `"certificate loaded"`, before+1)
	if got := servedSerial(t, httpsAddr); got.Cmp(third.Leaf.SerialNumber) != 0 {
		t.Fatal("SIGHUP did not serve the pair of the files")
	}
	if strings.Contains(s.logs.String(), "PRIVATE KEY") {
		t.Error("the service's log holds key material")
	}
}

// With tls.mode files a missing pair stops the service at startup, before any
// listener is opened.
//
// Covers: FR-52 (part), SEC-41 (part)
// Acceptance: Built-in TLS with files (part)
func TestServeWithFilesNeedsThePairAtStartup(t *testing.T) {
	e := server.New(t)
	enableTLSFiles(t, e)
	env := serviceConfigDir(t, e)
	var out, errb bytes.Buffer
	listens := 0
	a := &app{
		stdout: &out, stderr: &errb, clock: clock.Real(),
		getenv: func(k string) string { return env[k] },
		listen: func(context.Context, string, string) (net.Listener, error) { listens++; return nil, io.EOF },
	}
	if code := a.run(t.Context(), []string{"serve"}); code != 1 || listens != 0 || !strings.Contains(errb.String(), "tls.cert_file") {
		t.Fatalf("exit %d, listens %d, stderr %q", code, listens, errb.String())
	}
}

// FEATHERAUTH_LISTEN overrides listen, so with tls.mode files the address in use
// must be loopback: a service started with another one stops before it listens.
//
// Covers: FR-52 (part), SEC-41 (part)
// Acceptance: Built-in TLS with files (part)
func TestServeWithFilesRefusesANonLoopbackListenOverride(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "example.com:0"} {
		t.Run(addr, func(t *testing.T) {
			e := server.New(t)
			writeTLSPair(t, e.ConfigDir(), tlscert.New(t, "auth.example.com", "127.0.0.1"))
			enableTLSFiles(t, e)
			env := serviceConfigDir(t, e)
			env["FEATHERAUTH_LISTEN"] = addr
			var out, errb bytes.Buffer
			listens := 0
			a := &app{
				stdout: &out, stderr: &errb, clock: clock.Real(),
				getenv: func(k string) string { return env[k] },
				listen: func(context.Context, string, string) (net.Listener, error) { listens++; return nil, io.EOF },
			}
			if code := a.run(t.Context(), []string{"serve"}); code != 1 || listens != 0 || !strings.Contains(errb.String(), "FEATHERAUTH_LISTEN") {
				t.Fatalf("exit %d, listens %d, stderr %q", code, listens, errb.String())
			}
		})
	}
}
