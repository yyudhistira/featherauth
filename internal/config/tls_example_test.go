package config

import (
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/tlscert"
)

// The example server.yaml of built-in TLS loads with its pair, and it names the
// ports that deploy/compose.tls.yaml publishes (443 and 80 on the host).
//
// Covers: FR-52 (part)
// Acceptance: Built-in TLS with files (part)
func TestShippedTLSExampleLoadsClean(t *testing.T) {
	d := shippedDirWithSecrets(t)
	d.Server(t, string(shippedFile(t, "server.tls.yaml.example")))
	pair := tlscert.New(t, "auth.example.com", "127.0.0.1")
	d.Write(t, "secrets/tls_cert.pem", string(pair.CertPEM))
	d.Write(t, "secrets/tls_key.pem", string(pair.KeyPEM))
	_, ds := loadDir(t, d)
	if len(ds) != 0 {
		t.Fatalf("diagnostics: %v", ds)
	}
}

// Covers: FR-52 (part), SEC-41 (part)
// Acceptance: Built-in TLS with files (part)
func TestShippedTLSExampleSetsTheListeners(t *testing.T) {
	s, ds := DecodeServer("server.tls.yaml.example", shippedFile(t, "server.tls.yaml.example"))
	if s == nil || hasError(ds) {
		t.Fatalf("decoding: %v", ds)
	}
	want := map[string]string{
		"listen":          "127.0.0.1:8080",
		"tls.mode":        "files",
		"tls.listen":      ":8443",
		"tls.http_listen": ":8081",
		"tls.cert_file":   "secrets/tls_cert.pem",
		"tls.key_file":    "secrets/tls_key.pem",
		"public_url":      "https://auth.example.com",
	}
	got := map[string]string{
		"listen":          s.Listen,
		"tls.mode":        s.TLS.Mode,
		"tls.listen":      s.TLS.Listen,
		"tls.http_listen": s.TLS.HTTPListen,
		"tls.cert_file":   s.TLS.CertFile,
		"tls.key_file":    s.TLS.KeyFile,
		"public_url":      s.PublicURL,
	}
	if len(s.TrustedProxies) != 0 {
		t.Errorf("trusted_proxies %v, want none: the proxy-less mode", s.TrustedProxies)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q", k, got[k], w)
		}
	}
}
