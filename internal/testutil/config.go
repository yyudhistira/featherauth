package testutil

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
)

// DefaultClients is the clients block of MinimalRealm.
const DefaultClients = `clients:
  web:
    redirect_uris: [https://app.example.com/callback]
    web_origins: [https://app.example.com]
`

// RealmYAML returns a valid realm file with an RSA key at
// secrets/<name>/signing.pem and Google enabled with the secret
// secrets/<name>/google_client_secret; extra is appended as it is (clients,
// `enabled: false` and the like). NewConfig writes both files.
func RealmYAML(name, extra string) string {
	return "name: " + name + "\n" +
		"keys:\n  - { kid: " + name + "-1, file: secrets/" + name + "/signing.pem, state: active }\n" +
		"providers:\n  google:\n    enabled: true\n    client_id: google-id\n" +
		"    client_secret_file: secrets/" + name + "/google_client_secret\n" +
		extra
}

// MinimalRealm is RealmYAML with DefaultClients.
func MinimalRealm(name string) string { return RealmYAML(name, DefaultClients) }

// WriteRealm writes realms/<name>.yaml and the key and secret files that
// RealmYAML names.
func WriteRealm(t testing.TB, d *configdir.Dir, name, yaml string) {
	t.Helper()
	d.RSAKey(t, "secrets/"+name+"/signing.pem")
	d.Secret(t, "secrets/"+name+"/google_client_secret")
	d.Realm(t, name, yaml)
}

// NewConfigDir loads a configuration directory with the given server.yaml and
// realm files (name to YAML, see RealmYAML) and returns the loader and the
// directory, so a test can change files and call Reload. The loader's clock is
// fake.
func NewConfigDir(t testing.TB, serverYAML string, realms map[string]string) (*config.Loader, *configdir.Dir) {
	t.Helper()
	return NewConfigDirWithSecrets(t, serverYAML, realms)
}

// NewConfigDirWithSecrets is NewConfigDir that also writes a random secret to
// each of the given files (relative to the directory, such as
// secrets/main/srv_secret), for the client secrets a realm names; a name ending
// in .p8 gets an Apple key instead.
func NewConfigDirWithSecrets(t testing.TB, serverYAML string, realms map[string]string, secrets ...string) (*config.Loader, *configdir.Dir) {
	t.Helper()
	d := configdir.New(t)
	for _, s := range secrets {
		if strings.HasSuffix(s, ".p8") {
			d.AppleKey(t, s)
			continue
		}
		d.Secret(t, s)
	}
	d.Server(t, serverYAML)
	for name, y := range realms {
		WriteRealm(t, d, name, y)
	}
	d.EncryptionKey(t, "secrets/encryption_key")
	l, err := config.NewLoader(d.Root, clock.NewFake(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	return l, d
}

// NewConfigWithSecrets is NewConfigDirWithSecrets without the directory.
func NewConfigWithSecrets(t testing.TB, serverYAML string, realms map[string]string, secrets ...string) *config.Loader {
	t.Helper()
	l, _ := NewConfigDirWithSecrets(t, serverYAML, realms, secrets...)
	return l
}

// NewConfig is NewConfigDir without the directory.
func NewConfig(t testing.TB, serverYAML string, realms map[string]string) *config.Loader {
	t.Helper()
	l, _ := NewConfigDir(t, serverYAML, realms)
	return l
}

// ProvidersServerYAML is the server.yaml of NewProviderConfig.
const ProvidersServerYAML = "public_url: https://auth.example.com\n"

// ProvidersRealmYAML returns the realm "main" with the given providers block
// (the text under `providers:`, indented by two spaces), one client and a
// login-page contact. Secret files are named secrets/main/<key>_secret and the
// Apple key secrets/main/apple.p8; NewProviderConfig writes them.
func ProvidersRealmYAML(providers string) string {
	return "name: main\n" +
		"keys:\n  - { kid: main-1, file: secrets/main/signing.pem, state: active }\n" +
		"login_page:\n  contact: help@example.com\n" +
		"providers:\n" + providers +
		DefaultClients
}

// NewProviderConfig loads a configuration directory with one realm "main"
// whose providers block is given (see ProvidersRealmYAML). secretKeys lists
// the provider keys that need a client secret file. It returns the loader
// and the directory; WriteProviders changes the providers and reloads.
func NewProviderConfig(t testing.TB, providers string, secretKeys ...string) (*config.Loader, *configdir.Dir) {
	t.Helper()
	return NewProviderConfigWithServer(t, ProvidersServerYAML, providers, secretKeys...)
}

// NewProviderConfigWithServer is NewProviderConfig with the given server.yaml.
func NewProviderConfigWithServer(t testing.TB, serverYAML, providers string, secretKeys ...string) (*config.Loader, *configdir.Dir) {
	t.Helper()
	d := configdir.New(t)
	d.Server(t, serverYAML)
	d.RSAKey(t, "secrets/main/signing.pem")
	d.AppleKey(t, "secrets/main/apple.p8")
	for _, k := range secretKeys {
		d.Secret(t, "secrets/main/"+k+"_secret")
	}
	d.Realm(t, "main", ProvidersRealmYAML(providers))
	d.EncryptionKey(t, "secrets/encryption_key")
	l, err := config.NewLoader(d.Root, clock.NewFake(time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	return l, d
}

// WriteProviders replaces the providers of realm "main" and reloads; it fails
// the test when the reload is not applied.
func WriteProviders(t testing.TB, l *config.Loader, d *configdir.Dir, providers string) {
	t.Helper()
	d.Realm(t, "main", ProvidersRealmYAML(providers))
	if res := l.Reload(context.Background()); !res.Applied {
		t.Fatalf("reload not applied: %v", res.Diagnostics)
	}
}
