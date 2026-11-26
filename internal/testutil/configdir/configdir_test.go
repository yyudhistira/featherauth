package configdir_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
)

func TestFilesAreWrittenWithMode0600(t *testing.T) {
	d := configdir.New(t)
	d.Server(t, "public_url: https://auth.example.com\n")
	d.Realm(t, "main", "name: main\n")
	d.RSAKey(t, "secrets/a/rsa.pem")
	d.AppleKey(t, "secrets/a/apple.p8")
	d.Secret(t, "secrets/a/secret")
	d.EncryptionKey(t, "secrets/encryption_key")
	for _, f := range []string{"server.yaml", "realms/main.yaml", "secrets/a/rsa.pem", "secrets/a/apple.p8", "secrets/a/secret", "secrets/encryption_key"} {
		info, err := os.Stat(filepath.Join(d.Root, f))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %o", f, info.Mode().Perm())
		}
	}
	b, _ := os.ReadFile(filepath.Join(d.Root, "secrets/encryption_key"))
	if k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b))); err != nil || len(k) != 32 {
		t.Errorf("encryption key: %d bytes, %v", len(k), err)
	}
}
