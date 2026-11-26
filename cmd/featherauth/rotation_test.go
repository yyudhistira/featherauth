package main

import (
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/user"
)

// newKeyFile writes a new 32-byte encryption key into the configuration
// directory and returns its raw bytes.
func newKeyFile(t *testing.T, dir, rel string) []byte {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := io.ReadFull(secure.Default, raw); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, rel)
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return raw
}

// The stored Apple token follows the key rules of SEC-10 through a rotation:
// the new key seals, both keys open, the removal of the old key still lets a
// deletion complete (without the revoke), and a configuration that stores
// tokens without a key does not pass `config check`.
//
// Condition to test, SEC-10: AES-GCM with the first key, a key id in each value,
// every listed key decrypts, a 32-byte key, the id format, the id as AAD, the
// value format and a value with an unknown key id that cannot be opened: the
// box assertions below; a failed decryption at deletion completes it with a
// warning, and no key with store_refresh_token is an error: the CLI steps
// below. That the Apple login stores the refresh token encrypted at rest (the
// token this test seeds itself) is proved by TestAppleLoginStoresTheSealedRefreshToken
// (internal/oidc/callback_token_test.go): the stored value does not contain
// the token and opens to it with the configuration's key.
//
// Covers: SEC-10
// Acceptance: Encryption key rotation
func TestEncryptionKeyRotationEndToEnd(t *testing.T) {
	e := server.New(t)
	e.Login(t, server.ClientQuery)
	dir := e.ConfigDir()
	env := serviceConfigDir(t, e)
	serverYAML := filepath.Join(dir, "server.yaml")
	oldRaw, err := os.ReadFile(filepath.Join(dir, "secrets/encryption_key"))
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(oldRaw)))
	if err != nil {
		t.Fatal(err)
	}
	newKey := newKeyFile(t, dir, "secrets/encryption_key_new")

	// The value format: the id of the key (the first 8 hex characters of the
	// SHA-256 of the raw key), a dot, and the unpadded base64url of a 12-byte
	// nonce followed by the ciphertext and the tag.
	boxOld, err := secure.NewBox([][]byte{oldKey})
	if err != nil {
		t.Fatal(err)
	}
	boxNew, err := secure.NewBox([][]byte{newKey, oldKey})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := boxNew.Seal([]byte("apple-refresh-token"))
	if err != nil {
		t.Fatal(err)
	}
	id, payload, ok := strings.Cut(sealed, ".")
	raw, decodeErr := base64.RawURLEncoding.DecodeString(payload)
	if !ok || id != string(secure.HashOf(string(newKey)))[:8] || decodeErr != nil || len(raw) != 12+len("apple-refresh-token")+16 {
		t.Fatalf("sealed %q: id %q, payload of %d bytes, %v", sealed, id, len(raw), decodeErr)
	}
	// Only the first key seals, and the id is bound to the ciphertext.
	if _, err := boxOld.Open(sealed); err == nil {
		t.Error("a value sealed with the new key opens with the old key alone")
	}
	oldSealed, _ := boxOld.Seal([]byte("x"))
	oldID, oldPayload, _ := strings.Cut(oldSealed, ".")
	if _, err := boxNew.Open(id + "." + oldPayload); err == nil {
		t.Error("a ciphertext opens under another key's id")
	}
	if _, err := boxNew.Open(oldID + "." + payload); err == nil {
		t.Error("a ciphertext opens with its key id swapped")
	}
	// A key that is not 32 bytes is refused.
	if _, err := secure.NewBox([][]byte{newKey[:16]}); err == nil {
		t.Error("a 16-byte key was accepted")
	}

	revoking := func(rv *recordingRevoker) func(*app) {
		return func(a *app) {
			a.revokerFactory = func(config.Source, clock.Clock, *slog.Logger) user.RevokerFor {
				return func(realm, key string) provider.Revoker {
					if realm == "main" && key == "apple" {
						return rv
					}
					return nil
				}
			}
		}
	}

	// A new first key, the old one kept: the token sealed with the old key
	// decrypts and the revoke is called.
	uid := seedAppleToken(t, e, "apple-refresh-token")
	editFile(t, serverYAML, func(y string) string {
		return y + "secrets:\n  encryption_key_files: [secrets/encryption_key_new, secrets/encryption_key]\n"
	})
	rv := &recordingRevoker{}
	if r := execApp(t, e.Clock, env, revoking(rv), "user", "delete", "main", uid); r.code != 0 {
		t.Fatalf("both keys: %+v", r)
	}
	if len(rv.tokens) != 1 || rv.tokens[0] != "apple-refresh-token" {
		t.Fatalf("both keys: revoked %v", rv.tokens)
	}

	// The old key removed: the deletion completes, the revoke is skipped and
	// a warning is logged without the token.
	e.Login(t, server.ClientQuery) // the user comes back with a new id
	uid = seedAppleToken(t, e, "second-apple-token")
	editFile(t, serverYAML, func(y string) string {
		return strings.Replace(y, "[secrets/encryption_key_new, secrets/encryption_key]", "[secrets/encryption_key_new]", 1)
	})
	rv = &recordingRevoker{}
	r := execApp(t, e.Clock, env, revoking(rv), "user", "delete", "main", uid)
	if r.code != 0 || len(rv.tokens) != 0 || !strings.Contains(r.stderr, `"level":"WARN"`) || strings.Contains(r.stderr, "second-apple-token") {
		t.Fatalf("old key removed: %+v, revoked %v", r, rv.tokens)
	}
	if got := execAt(t, e.Clock, env, "user", "get", "main", uid); got.code != 1 {
		t.Fatalf("the user is still there: %+v", got)
	}

	// store_refresh_token with no encryption key fails config check.
	editFile(t, serverYAML, func(y string) string {
		return strings.Replace(y, "encryption_key_files: [secrets/encryption_key_new]", "encryption_key_files: []", 1)
	})
	if r := execAt(t, e.Clock, env, "config", "check", dir); r.code == 0 || !strings.Contains(r.stdout+r.stderr, "store_refresh_token needs an encryption key") {
		t.Fatalf("config check without a key: %+v", r)
	}
}
