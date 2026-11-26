package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// keycloakDir copies the structure of testdata/keycloak into a temporary directory
// and generates its secret files at mode 0600 with the CLI: no secret is copied
// and git never holds a file at mode 0600.
func keycloakDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	err := filepath.WalkDir("testdata/keycloak", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel("testdata/keycloak", p)
		if err != nil {
			return err
		}
		target := filepath.Join(dir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets/main"), 0o700); err != nil {
		t.Fatal(err)
	}
	if r := exec(t, nil, "keys", "generate", "--type", "encryption", filepath.Join(dir, "secrets/encryption_key")); r.code != 0 {
		t.Fatalf("keys generate encryption: %+v", r)
	}
	if r := exec(t, nil, "keys", "generate", "--type", "rsa", filepath.Join(dir, "secrets/main/signing-2026-11.pem")); r.code != 0 {
		t.Fatalf("keys generate rsa: %+v", r)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets/main/google_client_secret"), []byte("placeholder-google-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The structure of an existing deployment, with placeholder values, passes
// config check with no error: its public client sends no PKCE challenge
// (require_pkce: false) and stays within FR-32 at 30 minutes idle and 10 hours
// session. With the idle lifetime at 25 hours the same copy is refused, with the
// reason of FR-32, so the first check is not an empty one.
//
// Covers: FR-32, SEC-01
// Acceptance: PKCE exception limits (part)
func TestConfigCheckAcceptsAKeycloakStyleConfiguration(t *testing.T) {
	dir := keycloakDir(t)
	r := exec(t, nil, "config", "check", dir)
	if r.code != 0 || strings.Contains(r.stdout, ": error:") || strings.Contains(r.stderr, ": error:") {
		t.Fatalf("config check: %+v", r)
	}
	// The client is accepted with the RFC 9700 warning for a public client without PKCE.
	if !strings.Contains(r.stdout, "warning: clients.app.require_pkce") || !strings.Contains(r.stdout, "RFC 9700 section 2.1.1") {
		t.Fatalf("config check does not warn about the PKCE exception: %+v", r)
	}

	realm := filepath.Join(dir, "realms/main.yaml")
	y := strings.Replace(read(t, realm), "refresh_idle_lifetime: 30m", "refresh_idle_lifetime: 25h", 1)
	if err := os.WriteFile(realm, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	const reason = "client app: a public client with require_pkce: false needs refresh_idle_lifetime of at most 24h"
	if r := exec(t, nil, "config", "check", dir); r.code != 1 || !strings.Contains(r.stdout, reason) {
		t.Fatalf("config check at 25h: %+v", r)
	}
}
