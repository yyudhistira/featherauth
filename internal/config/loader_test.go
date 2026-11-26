package config_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/config/configtest"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/secure"
)

// Covers: FR-17 (part)
// Acceptance: Startup (part)
func TestNewLoaderFailsWithoutValidConfiguration(t *testing.T) {
	cases := []struct {
		name  string
		setup func(d *cfgDir)
		file  string // file of an error diagnostic
	}{
		{"server.yaml invalid", func(d *cfgDir) {
			d.realm("main", "Main", "")
			d.write("server.yaml", "public_url: https://auth.example.com\nbogus: 1\n", 0o600)
		}, "server.yaml"},
		{"server.yaml missing public_url", func(d *cfgDir) { d.realm("main", "Main", ""); d.write("server.yaml", "listen: \":9000\"\n", 0o600) }, "server.yaml"},
		{"server.yaml missing", func(d *cfgDir) { d.realm("main", "Main", ""); d.remove("server.yaml") }, "server.yaml"},
		{"server.yaml not YAML", func(d *cfgDir) { d.realm("main", "Main", ""); d.write("server.yaml", "public_url: [\n", 0o600) }, "server.yaml"},
		{"database.yaml invalid", func(d *cfgDir) { d.realm("main", "Main", ""); d.write("database.yaml", "driver: mysql\n", 0o600) }, "database.yaml"},
		{"database.yaml unknown option", func(d *cfgDir) { d.realm("main", "Main", ""); d.write("database.yaml", "nope: 1\n", 0o600) }, "database.yaml"},
		{"no realms directory", func(d *cfgDir) {}, "realms"},
		{"empty realms directory", func(d *cfgDir) { _ = os.MkdirAll(filepath.Join(d.root, "realms"), 0o700) }, "realms"},
		{"only an invalid realm", func(d *cfgDir) { d.write("realms/main.yaml", "name: main\nbogus: 1\n", 0o600) }, "realms/main.yaml"},
		{"only a realm with a missing key file", func(d *cfgDir) { d.realm("main", "Main", ""); d.remove("secrets/main/signing.pem") }, "realms/main.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newCfgDir(t)
			tc.setup(d)
			l, err := config.NewLoader(d.root, newFake(), nil)
			if err == nil || l != nil {
				t.Fatalf("NewLoader = %v, %v; want an error and no loader", l, err)
			}
			var le *config.LoadError
			if !errors.As(err, &le) {
				t.Fatalf("error %T is not a *config.LoadError", err)
			}
			if !hasDiag(le.Diagnostics, tc.file, config.Error, "") {
				t.Errorf("no error diagnostic for %s in %v", tc.file, le.Diagnostics)
			}
			if !strings.Contains(err.Error(), tc.file) {
				t.Errorf("error text %q does not name %s", err, tc.file)
			}
		})
	}
}

// Covers: FR-17 (part)
// Acceptance: Startup (part)
func TestNewLoaderLoadsDefaultLayoutAndAppliesDefaults(t *testing.T) {
	d := newCfgDir(t)
	d.realm("main", "Main", "")
	d.realm("second", "Second", "")
	l, _, _ := d.loader(t)
	s := l.Current()
	if s == nil {
		t.Fatal("Current() is nil")
	}
	if got := len(s.Realms()); got != 2 {
		t.Fatalf("%d realms, want 2", got)
	}
	if got := s.Server().Listen; got != ":8080" {
		t.Errorf("listen = %q, want the default :8080", got)
	}
	if got := s.Database().Driver; got != "sqlite" {
		t.Errorf("database driver = %q, want the default sqlite (database.yaml is optional)", got)
	}
	r, _ := s.Realm("main")
	if got := r.Issuer(); got != "https://auth.example.com/main" {
		t.Errorf("issuer = %q", got)
	}
	if s.Secrets() == nil {
		t.Error("snapshot has no secrets")
	}
	if kid := r.Keys[0].Kid; s.Secrets().Signing(kid) == nil {
		t.Errorf("signing key %s not loaded", kid)
	}
}

func TestLoadErrorListsEveryError(t *testing.T) {
	err := &config.LoadError{Diagnostics: []config.Diagnostic{
		{File: "a.yaml", Line: 2, Severity: config.Error, Message: "first"},
		{File: "b.yaml", Severity: config.Warning, Message: "only a warning"},
		{File: "c.yaml", Field: "x", Severity: config.Error, Message: "second"},
	}}
	got := err.Error()
	for _, want := range []string{"a.yaml:2", "first", "c.yaml", "second"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q does not contain %q", got, want)
		}
	}
	if strings.Contains(got, "only a warning") {
		t.Errorf("%q lists a warning", got)
	}
}

// Covers: FR-18 (part)
// Acceptance: Bad reload (part)
func TestReloadBrokenRealmKeepsLastGoodAndOthersReload(t *testing.T) {
	breakers := []struct {
		name string
		do   func(d *cfgDir)
	}{
		{"invalid YAML", func(d *cfgDir) { d.write("realms/a.yaml", "name: a\nkeys: [\n", 0o600) }},
		{"unknown option", func(d *cfgDir) { d.write("realms/a.yaml", "name: a\ntypo_option: 1\n", 0o600) }},
		{"missing secret file", func(d *cfgDir) { d.remove("secrets/a/signing.pem") }},
		{"validation error", func(d *cfgDir) { d.realm("a", "A2", "tokens:\n  algorithm: HS256\n") }},
		{"file name and name differ", func(d *cfgDir) {
			d.realm("a", "A2", "")
			d.write("realms/a.yaml", strings.Replace(readFile(t, d, "realms/a.yaml"), "name: a", "name: other", 1), 0o600)
		}},
	}
	for _, br := range breakers {
		t.Run(br.name, func(t *testing.T) {
			d := newCfgDir(t)
			d.realm("a", "A1", "")
			d.realm("b", "B1", "")
			l, _, logs := d.loader(t)

			br.do(d)
			d.realm("b", "B2", "")
			res := l.Reload(context.Background())

			if !hasDiag(res.Diagnostics, "realms/a.yaml", config.Error, "") && !hasDiag(res.Diagnostics, "secrets/a/signing.pem", config.Error, "") {
				t.Errorf("no error diagnostic for realm a: %v", res.Diagnostics)
			}
			for _, dg := range errorsOf(res.Diagnostics) {
				if strings.HasPrefix(dg.File, "realms/b") {
					t.Errorf("realm b is blamed for realm a's problem: %v", dg)
				}
			}
			if !res.Applied {
				t.Error("Applied = false, want true: realm b changed")
			}
			s := l.Current()
			a, ok := s.Realm("a")
			if !ok || a.DisplayName != "A1" {
				t.Errorf("realm a = %+v, %v; want the last good version (A1)", a, ok)
			}
			if b, _ := s.Realm("b"); b == nil || b.DisplayName != "B2" {
				t.Errorf("realm b = %+v; want the new version (B2)", b)
			}
			if st := l.Status().Stale; len(st) != 1 || st[0] != "a" {
				t.Errorf("Status().Stale = %v, want [a]", st)
			}
			if !strings.Contains(logs.String(), "realms/a.yaml") {
				t.Errorf("the error is not logged with its file: %s", logs.String())
			}

			// Fixing the file ends the stale state.
			d.realm("a", "A3", "")
			res = l.Reload(context.Background())
			if len(errorsOf(res.Diagnostics)) != 0 {
				t.Fatalf("errors after the fix: %v", res.Diagnostics)
			}
			if a, _ := l.Current().Realm("a"); a.DisplayName != "A3" {
				t.Errorf("realm a = %q after the fix, want A3", a.DisplayName)
			}
			if st := l.Status().Stale; len(st) != 0 {
				t.Errorf("Status().Stale = %v after the fix", st)
			}
		})
	}
}

func readFile(t *testing.T, d *cfgDir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d.root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Covers: FR-18 (part)
// Acceptance: Bad reload (part)
func TestReloadNewBrokenRealmIsNotServed(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A", "")
	l, _, _ := d.loader(t)
	d.write("realms/c.yaml", "name: c\nbogus: 1\n", 0o600)
	res := l.Reload(context.Background())
	if !hasDiag(res.Diagnostics, "realms/c.yaml", config.Error, "") {
		t.Fatalf("no error for the new broken realm: %v", res.Diagnostics)
	}
	if _, ok := l.Current().Realm("c"); ok {
		t.Error("a realm that never was valid is served")
	}
	if _, ok := l.Current().Realm("a"); !ok {
		t.Error("realm a lost")
	}
	if len(l.Status().Stale) != 0 {
		t.Errorf("a realm that never was valid is not stale: %v", l.Status().Stale)
	}
}

// Covers: FR-15 (part)
func TestReloadRemovedRealmFileRemovesTheRealm(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A", "")
	d.realm("b", "B", "")
	l, _, _ := d.loader(t)
	d.remove("realms/b.yaml")
	res := l.Reload(context.Background())
	if !res.Applied {
		t.Fatalf("not applied: %v", res.Diagnostics)
	}
	s := l.Current()
	if _, ok := s.Realm("b"); ok {
		t.Error("realm b still served after its file was removed")
	}
	if _, ok := s.Realm("a"); !ok {
		t.Error("realm a lost")
	}
	if len(l.Status().Stale) != 0 {
		t.Errorf("a removed realm is not stale: %v", l.Status().Stale)
	}
}

// Covers: FR-17 (part)
func TestReloadWithoutAnyValidRealmKeepsTheLastGood(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A", "")
	l, _, _ := d.loader(t)
	before := l.Current()
	d.remove("realms/a.yaml")
	res := l.Reload(context.Background())
	if res.Applied {
		t.Error("Applied = true although no realm is left")
	}
	if !hasDiag(res.Diagnostics, "realms", config.Error, "") {
		t.Errorf("no error about the missing realms: %v", res.Diagnostics)
	}
	if l.Current() != before {
		t.Error("the snapshot changed")
	}
}

// Covers: FR-18 (part), FR-25 (part)
// Acceptance: Server config change (part)
func TestReloadAppliesLiveOptionsAndReportsRestartOptions(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A", "")
	d.write("database.yaml", "sqlite:\n  path: /var/lib/a.db\n", 0o600)
	l, _, logs := d.loader(t)

	// A live option applies at once, with nothing to report.
	d.write("server.yaml", "public_url: https://auth.example.com\nlog_level: debug\ntrusted_proxies: [10.0.0.0/8]\nrate_limit:\n  per_ip_per_minute: 5\nlogin:\n  provider_hint_params: [idp]\nlogout:\n  redirect_params: [back]\n", 0o600)
	res := l.Reload(context.Background())
	if !res.Applied || len(res.RestartRequired) != 0 {
		t.Fatalf("live change: applied=%v restart=%v diags=%v", res.Applied, res.RestartRequired, res.Diagnostics)
	}
	srv := l.Current().Server()
	if srv.LogLevel != "debug" || !reflect.DeepEqual(srv.TrustedProxies, []string{"10.0.0.0/8"}) || srv.RateLimit.PerIPPerMinute != 5 ||
		!reflect.DeepEqual(srv.Login.ProviderHintParams, []string{"idp"}) || !reflect.DeepEqual(srv.Logout.RedirectParams, []string{"back"}) {
		t.Errorf("live options not applied: %+v", srv)
	}

	// A restart option is reported, and the old value stays.
	d.write("server.yaml", "public_url: https://other.example.com\nlisten: \":9090\"\nlog_level: warn\n", 0o600)
	res = l.Reload(context.Background())
	want := []string{"server.yaml:listen", "server.yaml:public_url"}
	if !reflect.DeepEqual(res.RestartRequired, want) {
		t.Fatalf("RestartRequired = %v, want %v", res.RestartRequired, want)
	}
	srv = l.Current().Server()
	if srv.PublicURL != "https://auth.example.com" || srv.Listen != ":8080" {
		t.Errorf("restart options changed: public_url=%q listen=%q", srv.PublicURL, srv.Listen)
	}
	if srv.LogLevel != "warn" {
		t.Errorf("log_level = %q, the live option changed in the same edit and must apply", srv.LogLevel)
	}
	if r, _ := l.Current().Realm("a"); r.Issuer() != "https://auth.example.com/a" {
		t.Errorf("issuer = %q; it must keep the running public_url", r.Issuer())
	}
	if !res.Applied {
		t.Error("Applied = false, want true: log_level changed")
	}
	out := logs.String()
	for _, w := range []string{"restart required", "server.yaml:listen", "server.yaml:public_url"} {
		if !strings.Contains(out, w) {
			t.Errorf("log lacks %q: %s", w, out)
		}
	}

	// Back to the running values: nothing to report.
	d.write("server.yaml", "public_url: https://auth.example.com\n", 0o600)
	if res = l.Reload(context.Background()); len(res.RestartRequired) != 0 {
		t.Errorf("RestartRequired = %v after reverting", res.RestartRequired)
	}

	// database.yaml changes are restart too, and the old values keep running.
	d.write("database.yaml", "sqlite:\n  path: /var/lib/b.db\nbackup:\n  keep: 3\n", 0o600)
	res = l.Reload(context.Background())
	want = []string{"database.yaml:backup.keep", "database.yaml:sqlite.path"}
	if !reflect.DeepEqual(res.RestartRequired, want) {
		t.Fatalf("RestartRequired = %v, want %v", res.RestartRequired, want)
	}
	if db := l.Current().Database(); db.SQLite.Path != "/var/lib/a.db" || db.Backup.Keep != 7 {
		t.Errorf("database options changed at runtime: %+v", db)
	}
}

// Covers: FR-18 (part)
// Acceptance: Server config change (part)
func TestReloadInvalidServerOrDatabaseFileIsIgnored(t *testing.T) {
	for _, file := range []string{"server.yaml", "database.yaml"} {
		t.Run(file, func(t *testing.T) {
			d := newCfgDir(t)
			d.realm("a", "A1", "")
			l, _, _ := d.loader(t)
			d.write(file, "bogus_option: 1\n", 0o600)
			d.realm("a", "A2", "")
			res := l.Reload(context.Background())
			if !hasDiag(res.Diagnostics, file, config.Error, "bogus_option") {
				t.Fatalf("no diagnostic for %s: %v", file, res.Diagnostics)
			}
			s := l.Current()
			if got := s.Server().PublicURL; got != "https://auth.example.com" {
				t.Errorf("public_url = %q after an invalid %s", got, file)
			}
			if r, _ := s.Realm("a"); r.DisplayName != "A2" {
				t.Errorf("realm a = %q; realms reload independently of an invalid %s", r.DisplayName, file)
			}
			if len(res.RestartRequired) != 0 {
				t.Errorf("restart reported for an invalid file: %v", res.RestartRequired)
			}
		})
	}
}

// Covers: FR-18 (part), FR-25 (part)
func TestServerOptionClassesMatchTheDesign(t *testing.T) {
	raw, err := os.ReadFile("../../docs/DESIGN.md")
	if err != nil {
		t.Fatal(err)
	}
	design := map[string]bool{}
	in := false
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "#### `server.yaml`"):
			in = true
			continue
		case strings.HasPrefix(line, "#### ") && in:
			in = false
		}
		if !in || !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "| "), " | ")
		opt := strings.Trim(cells[0], "`")
		switch effect := strings.TrimSpace(cells[len(cells)-1]); effect {
		case "live":
			design[opt] = true
		case "restart":
			design[opt] = false
		default:
			t.Fatalf("option %s: unknown 'Takes effect' value %q", opt, effect)
		}
	}
	if len(design) < 20 {
		t.Fatalf("read only %d options from the design", len(design))
	}
	names := config.ServerOptionNames()
	for opt, live := range design {
		got, known := config.ServerOptionLive(opt)
		if !known || got != live {
			t.Errorf("option %s: loader live=%v known=%v, design live=%v", opt, got, known, live)
		}
	}
	for _, n := range names {
		if _, ok := design[n]; !ok {
			t.Errorf("ServerFile option %s is not in the design table", n)
		}
	}
	if len(names) != len(design) {
		t.Errorf("%d options in ServerFile, %d in the design", len(names), len(design))
	}
}

// Covers: FR-15 (part)
func TestRealmNameMustBeUniqueAcrossFiles(t *testing.T) {
	a := &config.RealmFile{Name: "main"}
	b := &config.RealmFile{Name: "other"}
	c := &config.RealmFile{Name: "main"}
	ds := config.CheckDuplicateRealms([]config.RealmSource{
		{File: "realms/a.yaml", Realm: a}, {File: "realms/b.yaml", Realm: b}, {File: "realms/c.yaml", Realm: c},
	})
	if len(ds) != 1 || ds[0].File != "realms/c.yaml" || ds[0].Severity != config.Error || ds[0].Field != "name" || !strings.Contains(ds[0].Message, "realms/a.yaml") {
		t.Fatalf("diagnostics = %v, want one error on realms/c.yaml naming realms/a.yaml", ds)
	}
	if ds := config.CheckDuplicateRealms([]config.RealmSource{{File: "realms/a.yaml", Realm: a}, {File: "realms/b.yaml", Realm: b}}); len(ds) != 0 {
		t.Errorf("unique names reported: %v", ds)
	}
}

// Covers: FR-15 (part)
func TestRealmNameMustEqualItsFileSoTwoFilesCannotShareARealm(t *testing.T) {
	d := newCfgDir(t)
	d.realm("main", "Main", "")
	l, _, _ := d.loader(t)
	// A second file that claims the name "main".
	d.write("realms/copy.yaml", strings.Replace(readFile(t, d, "realms/main.yaml"), "display_name: Main", "display_name: Copy", 1), 0o600)
	res := l.Reload(context.Background())
	if !hasDiag(res.Diagnostics, "realms/copy.yaml", config.Error, "name") {
		t.Fatalf("no name error for the copy: %v", res.Diagnostics)
	}
	if r, _ := l.Current().Realm("main"); r.DisplayName != "Main" {
		t.Errorf("the copy overwrote realm main: %q", r.DisplayName)
	}
	if got := len(l.Current().Realms()); got != 1 {
		t.Errorf("%d realms, want 1", got)
	}
}

// Covers: SEC-07 (part)
func TestKeyIDsAreUniqueAcrossRealmsAndFallBackToLastGood(t *testing.T) {
	d := newCfgDir(t)
	d.realmKid("a", "ka", "A1", "")
	d.realmKid("b", "kb", "B1", "")
	l, _, _ := d.loader(t)

	// b reuses a's kid: b is the later file, so b is refused and keeps kb.
	d.realmKid("b", "ka", "B2", "")
	res := l.Reload(context.Background())
	if !hasDiag(res.Diagnostics, "realms/b.yaml", config.Error, "keys[0].kid") {
		t.Fatalf("no kid error on b: %v", res.Diagnostics)
	}
	s := l.Current()
	if b, _ := s.Realm("b"); b.DisplayName != "B1" || b.Keys[0].Kid != "kb" {
		t.Errorf("realm b = %q/%q, want the last good B1/kb", b.DisplayName, b.Keys[0].Kid)
	}
	if a, _ := s.Realm("a"); a.DisplayName != "A1" {
		t.Errorf("realm a = %q", a.DisplayName)
	}

	// a now takes kb, which the kept version of b still uses: a (the earlier
	// file) wins the kid in order, so b's last good version is the conflict
	// and is dropped only if it has to be; the result must hold no duplicate.
	d.realmKid("b", "kb", "B3", "")
	d.realmKid("a", "kb", "A2", "")
	res = l.Reload(context.Background())
	seen := map[string]string{}
	for _, r := range l.Current().Realms() {
		for _, k := range r.Keys {
			if other, dup := seen[k.Kid]; dup {
				t.Errorf("kid %s served by realms %s and %s", k.Kid, other, r.Name)
			}
			seen[k.Kid] = string(r.Name)
		}
	}
	if len(errorsOf(res.Diagnostics)) == 0 {
		t.Error("no error reported for the duplicate kid")
	}
}

// Covers: SEC-07 (part)
func TestKeyRulesNeverPassWithoutLoadedSecrets(t *testing.T) {
	_, ecPEM := testKeys(t)
	cases := []struct {
		name  string
		setup func(d *cfgDir)
		field string
		file  string
	}{
		{"key file missing", func(d *cfgDir) { d.remove("secrets/a/signing.pem") }, "keys[0].file", "realms/a.yaml"},
		{"key file not a key", func(d *cfgDir) { d.write("secrets/a/signing.pem", "not a key", 0o600) }, "keys[0].file", "realms/a.yaml"},
		{"no active RSA key", func(d *cfgDir) {
			d.write("realms/a.yaml", "name: a\nkeys:\n  - { kid: ka, file: secrets/a/signing.pem, state: verify_only }\n", 0o600)
		}, "keys", "realms/a.yaml"},
		{"only an EC key with RS256", func(d *cfgDir) {
			d.write("secrets/a/signing.pem", string(ecPEM), 0o600)
		}, "keys", "realms/a.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newCfgDir(t)
			d.realm("keep", "Keep", "")
			d.realmKid("a", "ka", "A", "")
			tc.setup(d)
			_, err := config.NewLoader(d.root, newFake(), nil)
			if err != nil {
				t.Fatalf("realm keep is valid, NewLoader = %v", err)
			}
			l, _, _ := loaderIn(t, d)
			if _, ok := l.Current().Realm("a"); ok {
				t.Error("realm a is served although its keys are not usable")
			}
			res := l.Reload(context.Background())
			if !hasDiag(res.Diagnostics, tc.file, config.Error, tc.field) {
				t.Errorf("no error on %s %s: %v", tc.file, tc.field, res.Diagnostics)
			}
		})
	}
}

func loaderIn(t *testing.T, d *cfgDir) (*config.Loader, interface{}, interface{}) {
	t.Helper()
	l, err := config.NewLoader(d.root, newFake(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return l, nil, nil
}

// Covers: FR-15 (part)
// Acceptance: Locale (part)
func TestLocaleFilesLoadWithTheirRealm(t *testing.T) {
	d := newCfgDir(t)
	nl := "login_page:\n  default_locale: en\n  supported_locales: [en, nl]\n"
	d.realm("a", "A", nl)
	d.realm("b", "B", "")
	if _, err := config.NewLoader(d.root, newFake(), nil); err != nil {
		// b is valid, so startup succeeds even though a lists a missing file.
		t.Fatalf("NewLoader = %v", err)
	}
	l, _, _ := d.loader(t)
	if _, ok := l.Current().Realm("a"); ok {
		t.Fatal("realm a lists nl without locales/nl.yaml and must be refused")
	}

	d.write("locales/nl.yaml", "login.title: Inloggen\nerror.title: Fout\n", 0o600)
	res := l.Reload(context.Background())
	if len(errorsOf(res.Diagnostics)) != 0 {
		t.Fatalf("errors after adding the locale: %v", res.Diagnostics)
	}
	a, ok := l.Current().Realm("a")
	if !ok {
		t.Fatal("realm a not served after locales/nl.yaml appeared")
	}
	m := a.Messages("nl")
	if m["login.title"] != "Inloggen" || m["error.title"] != "Fout" {
		t.Errorf("Messages(nl) = %v", m)
	}
	m["login.title"] = "mutated"
	if a.Messages("nl")["login.title"] != "Inloggen" {
		t.Error("Messages returned the stored map, not a copy")
	}
	if a.Messages("en") != nil || a.Messages("fr") != nil {
		t.Error("Messages of a locale without a translation file must be nil")
	}
	if b, _ := l.Current().Realm("b"); b.Messages("nl") != nil {
		t.Error("realm b does not list nl and must not load it")
	}

	// An edit of the translation applies at the next reload.
	d.write("locales/nl.yaml", "login.title: Aanmelden\n", 0o600)
	l.Reload(context.Background())
	if a, _ := l.Current().Realm("a"); a.Messages("nl")["login.title"] != "Aanmelden" {
		t.Errorf("edited translation not applied: %v", a.Messages("nl"))
	}

	// A broken translation keeps the realm's last good version.
	d.write("locales/nl.yaml", "login:\n  - not a text\n", 0o600)
	res = l.Reload(context.Background())
	if !hasDiag(res.Diagnostics, "locales/nl.yaml", config.Error, "") {
		t.Errorf("no error on locales/nl.yaml: %v", res.Diagnostics)
	}
	if a, _ := l.Current().Realm("a"); a.Messages("nl")["login.title"] != "Aanmelden" {
		t.Errorf("realm a lost its last good translation: %v", a.Messages("nl"))
	}

	// Removing the translation file makes the realm that lists it invalid.
	d.remove("locales/nl.yaml")
	res = l.Reload(context.Background())
	if !hasDiag(res.Diagnostics, "realms/a.yaml", config.Error, "login_page.supported_locales[1]") {
		t.Errorf("no error for the missing translation: %v", res.Diagnostics)
	}
}

// Covers: FR-15 (part)
func TestLocaleCodeCannotEscapeTheLocalesDirectory(t *testing.T) {
	d := newCfgDir(t)
	d.realm("ok", "OK", "")
	d.realm("a", "A", "login_page:\n  default_locale: en\n  supported_locales: [en, \"../secrets/a/signing\"]\n")
	d.write("secrets/a/signing.yaml", "k: v\n", 0o600)
	l, _, _ := d.loader(t)
	if _, ok := l.Current().Realm("a"); ok {
		t.Error("a locale code with a path was accepted")
	}
}

// Covers: SEC-13 (part)
func TestReloadSurfacesWarningsAndLeaksNoSecrets(t *testing.T) {
	const secret = "SENTINEL-loader-s3cr3t-1f9a"
	d := newCfgDir(t)
	d.write("server.yaml", "public_url: https://auth.example.com\nstrict_permissions: false\n", 0o600)
	d.realm("a", "A", "providers:\n  google:\n    enabled: true\n    client_id: id\n    client_secret_file: secrets/a/google\n")
	d.write("secrets/a/google", secret+"\n", 0o644)
	l, _, logs := d.loader(t)
	res := l.Reload(context.Background())
	if !hasDiag(res.Diagnostics, "realms/a.yaml", config.Warning, "providers.google.client_secret_file") {
		t.Fatalf("the loose permissions are not reported: %v", res.Diagnostics)
	}
	if _, ok := l.Current().Realm("a"); !ok {
		t.Fatal("a warning must not refuse the realm")
	}
	if got := l.Current().Secrets().ClientSecret("a", config.ProviderSecret, "google"); got != secret {
		t.Errorf("secret not loaded")
	}
	d.remove("secrets/a/signing.pem")
	res = l.Reload(context.Background())
	all := logs.String()
	for _, dg := range res.Diagnostics {
		all += dg.String()
	}
	if strings.Contains(all, secret) {
		t.Error("a secret reached a log line or diagnostic")
	}
	if strings.Contains(logs.String(), "-----BEGIN") {
		t.Error("key material in the log")
	}
}

// Covers: FR-18 (part)
func TestReloadDiagnosticsAreDeterministic(t *testing.T) {
	d := newCfgDir(t)
	d.realm("keep", "Keep", "")
	l, _, _ := d.loader(t)
	d.write("server.yaml", "public_url: https://auth.example.com\nx1: 1\nx2: 2\n", 0o600)
	d.write("database.yaml", "y1: 1\n", 0o600)
	for _, n := range []string{"z", "m", "c", "a", "q"} {
		d.write("realms/"+n+".yaml", "name: "+n+"\nbogus_"+n+": 1\nother_"+n+": 2\n", 0o600)
	}
	first := l.Reload(context.Background()).Diagnostics
	if len(errorsOf(first)) < 12 {
		t.Fatalf("only %d error diagnostics: %v", len(errorsOf(first)), first)
	}
	for range 5 {
		if got := l.Reload(context.Background()).Diagnostics; !reflect.DeepEqual(got, first) {
			t.Fatalf("diagnostics differ between reloads:\n%v\n%v", first, got)
		}
	}
	order := map[string]int{"server.yaml": 0, "database.yaml": 1}
	last := -1
	for _, dg := range first {
		rank, ok := order[dg.File]
		if !ok {
			rank = 2
		}
		if rank < last {
			t.Fatalf("diagnostics not ordered server.yaml, database.yaml, realms: %v", first)
		}
		last = rank
	}
	var realmFiles []string
	for _, dg := range first {
		if strings.HasPrefix(dg.File, "realms/") && (len(realmFiles) == 0 || realmFiles[len(realmFiles)-1] != dg.File) {
			realmFiles = append(realmFiles, dg.File)
		}
	}
	want := []string{"realms/a.yaml", "realms/c.yaml", "realms/m.yaml", "realms/q.yaml", "realms/z.yaml"}
	if !reflect.DeepEqual(realmFiles, want) {
		t.Errorf("realm diagnostics in order %v, want %v", realmFiles, want)
	}
}

// Covers: FR-18 (part)
func TestReloadWithCancelledContextChangesNothing(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A1", "")
	l, _, _ := d.loader(t)
	before := l.Current()
	d.realm("a", "A2", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := l.Reload(ctx)
	if res.Applied || len(errorsOf(res.Diagnostics)) == 0 || l.Current() != before {
		t.Errorf("a cancelled reload applied: %+v", res)
	}
}

func TestStatusTracksReloads(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A", "")
	l, clk, _ := d.loader(t)
	st := l.Status()
	if !st.LoadedAt.Equal(testStart) || !st.LastReload.Equal(testStart) {
		t.Fatalf("status at start = %+v", st)
	}
	clk.Advance(time.Hour)
	d.write("server.yaml", "public_url: https://other.example.com\n", 0o600)
	res := l.Reload(context.Background())
	st = l.Status()
	if !st.LoadedAt.Equal(testStart.Add(time.Hour)) || !st.LastReload.Equal(testStart.Add(time.Hour)) {
		t.Errorf("status after reload = %+v", st)
	}
	if !reflect.DeepEqual(st.Last, res) {
		t.Errorf("Status().Last = %+v, want %+v", st.Last, res)
	}
	st.Last.RestartRequired[0] = "mutated"
	if l.Status().Last.RestartRequired[0] == "mutated" {
		t.Error("Status shares its slices with the loader")
	}
}

// Covers: FR-18 (part)
func TestCurrentUnderConcurrentReloads(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A0", "")
	d.realm("b", "B0", "")
	l, _, _ := d.loader(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				s := l.Current()
				if s == nil || len(s.Realms()) != 2 {
					t.Error("Current() returned a snapshot without both realms")
					return
				}
				_ = l.Status()
			}
		}()
	}
	var rw sync.WaitGroup
	for i := range 4 {
		rw.Add(1)
		go func() {
			defer rw.Done()
			for range 10 {
				if res := l.Reload(context.Background()); len(errorsOf(res.Diagnostics)) != 0 {
					t.Errorf("reload %d: %v", i, res.Diagnostics)
					return
				}
			}
		}()
	}
	rw.Wait()
	close(stop)
	wg.Wait()
}

// The loader is a config.Source and passes the same contract as Static.
func TestLoaderContract(t *testing.T) {
	configtest.RunSource(t, func(t *testing.T) config.Source {
		d := newCfgDir(t)
		d.realm("a", "A", "")
		d.realm("b", "B", "")
		l, _, _ := d.loader(t)
		return l
	})
}

const encKeyA = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\n"
const encKeyB = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=\n"

// Covers: FR-17 (part)
// Acceptance: Startup (part)
func TestUnloadableServerSecretsStopStartup(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A1", "")
	d.write("server.yaml", "public_url: https://auth.example.com\nsecrets:\n  encryption_key_files: [secrets/enc]\n", 0o600)
	d.write("secrets/enc", "not 32 bytes", 0o600)
	_, err := config.NewLoader(d.root, newFake(), nil)
	var le *config.LoadError
	if !errors.As(err, &le) || !hasDiag(le.Diagnostics, "server.yaml", config.Error, "secrets.encryption_key_files[0]") {
		t.Fatalf("NewLoader = %v, want a LoadError on the encryption key file", err)
	}
}

// Covers: FR-18 (part), FR-25 (part)
// Acceptance: Bad reload (part)
func TestReloadServerSecretFileFailuresAreReportedAndRealmsStillReload(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(d *cfgDir)
		break_ func(d *cfgDir)
		file   string
		field  string
	}{
		{"encryption key file unparseable",
			func(d *cfgDir) {
				d.write("server.yaml", "public_url: https://auth.example.com\nsecrets:\n  encryption_key_files: [secrets/enc]\n", 0o600)
				d.write("secrets/enc", encKeyA, 0o600)
			},
			func(d *cfgDir) { d.write("secrets/enc", "broken", 0o600) },
			"server.yaml", "secrets.encryption_key_files[0]"},
		{"encryption key file unreadable",
			func(d *cfgDir) {
				d.write("server.yaml", "public_url: https://auth.example.com\nsecrets:\n  encryption_key_files: [secrets/enc]\n", 0o600)
				d.write("secrets/enc", encKeyA, 0o600)
			},
			func(d *cfgDir) { _ = os.Chmod(filepath.Join(d.root, "secrets/enc"), 0) },
			"server.yaml", "secrets.encryption_key_files[0]"},
		{"postgres password file missing",
			func(d *cfgDir) {
				d.write("database.yaml", "driver: postgres\npostgres:\n  host: db\n  password_file: secrets/pg\n", 0o600)
				d.write("secrets/pg", "pw\n", 0o600)
			},
			func(d *cfgDir) { d.remove("secrets/pg") },
			"database.yaml", "postgres.password_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newCfgDir(t)
			d.realm("a", "A1", "")
			tc.setup(d)
			l, _, _ := d.loader(t)
			tc.break_(d)
			t.Cleanup(func() { _ = os.Chmod(filepath.Join(d.root, "secrets/enc"), 0o600) })
			d.realm("a", "A2", "")
			res := l.Reload(context.Background())
			if !res.Applied {
				t.Fatalf("not applied: realms must still reload: %v", res.Diagnostics)
			}
			if !hasDiag(res.Diagnostics, tc.file, config.Error, tc.field) {
				t.Errorf("no error on %s %s: %v", tc.file, tc.field, res.Diagnostics)
			}
			if a, _ := l.Current().Realm("a"); a.DisplayName != "A2" {
				t.Errorf("realm a = %q, want A2", a.DisplayName)
			}
			for _, dg := range errorsOf(res.Diagnostics) {
				if strings.HasPrefix(dg.File, "realms/") {
					t.Errorf("a realm is blamed for a server secret: %v", dg)
				}
			}
		})
	}
}

// Covers: FR-18 (part)
func TestServerSecretsAreReadAtStartupOnly(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A1", "")
	d.write("server.yaml", "public_url: https://auth.example.com\nsecrets:\n  encryption_key_files: [secrets/enc]\n", 0o600)
	d.write("secrets/enc", encKeyA, 0o600)
	l, _, _ := d.loader(t)
	want := l.Current().Secrets().EncryptionKeys()
	if len(want) != 1 {
		t.Fatalf("%d keys", len(want))
	}

	d.write("secrets/enc", encKeyB, 0o600)
	d.realm("a", "A2", "")
	res := l.Reload(context.Background())
	if !res.Applied || len(errorsOf(res.Diagnostics)) != 0 {
		t.Fatalf("reload: %+v", res)
	}
	if got := l.Current().Secrets().EncryptionKeys(); !reflect.DeepEqual(got, want) {
		t.Error("an encryption key changed on disk was picked up by a reload")
	}
	if a, _ := l.Current().Realm("a"); a.DisplayName != "A2" {
		t.Errorf("realm a = %q", a.DisplayName)
	}

	// Removing the file (optional here) changes nothing either.
	d.remove("secrets/enc")
	if res = l.Reload(context.Background()); !res.Applied {
		t.Fatalf("not applied: %v", res.Diagnostics)
	}
	if got := l.Current().Secrets().EncryptionKeys(); !reflect.DeepEqual(got, want) {
		t.Error("the running encryption keys were dropped")
	}
}

// Covers: FR-15 (part)
func TestReloadSkipsDotFilesInRealms(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A", "")
	d.write("realms/.#a.yaml", "garbage: [\n", 0o600)
	d.write("realms/.a.yaml.swp.yaml", "garbage: [\n", 0o600)
	l, _, _ := d.loader(t)
	res := l.Reload(context.Background())
	if len(res.Diagnostics) != 0 {
		t.Errorf("dot files produced diagnostics: %v", res.Diagnostics)
	}
	if got := len(l.Current().Realms()); got != 1 {
		t.Errorf("%d realms, want 1", got)
	}
}

func TestUnreadableDatabaseFileIsAnError(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A", "")
	if err := os.MkdirAll(filepath.Join(d.root, "database.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := config.NewLoader(d.root, newFake(), nil)
	var le *config.LoadError
	if !errors.As(err, &le) || !hasDiag(le.Diagnostics, "database.yaml", config.Error, "") {
		t.Fatalf("NewLoader = %v", err)
	}
}

// Covers: FR-18 (part), SEC-10 (part)
// Acceptance: Bad reload (part)
func TestReloadKeepsRealmWithStoredAppleTokensWhenEncryptionKeyIsConfigured(t *testing.T) {
	d := newCfgDir(t)
	d.write("server.yaml", "public_url: https://auth.example.com\nsecrets:\n  encryption_key_files: [secrets/enc]\n", 0o600)
	d.write("secrets/enc", encKeyA, 0o600)
	k, err := ecdsa.GenerateKey(elliptic.P256(), secure.Default)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	d.write("secrets/apple.p8", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), 0o600)
	apple := "providers:\n  apple:\n    enabled: true\n    client_id: cid\n    store_refresh_token: true\n    team_id: TEAM123456\n    key_id: KEY1234567\n    private_key_file: secrets/apple.p8\n"
	d.realm("a", "A1", apple)
	l, _, _ := d.loader(t)

	d.realm("a", "A2", apple)
	res := l.Reload(context.Background())
	if !res.Applied || len(errorsOf(res.Diagnostics)) != 0 {
		t.Fatalf("reload with store_refresh_token and a key: applied=%v %v", res.Applied, res.Diagnostics)
	}
	if a, _ := l.Current().Realm("a"); a.DisplayName != "A2" {
		t.Errorf("realm a = %q, want A2", a.DisplayName)
	}
}

// OnApply hooks run after each reload that is applied, with the new snapshot,
// and not after one that is not.
func TestOnApplyRunsAfterAnAppliedReload(t *testing.T) {
	d := newCfgDir(t)
	d.realm("a", "A1", "")
	l, _, _ := d.loader(t)
	var seen []*config.Snapshot
	l.OnApply(func(_ context.Context, s *config.Snapshot) { seen = append(seen, s) })

	d.realm("a", "A2", "")
	if res := l.Reload(context.Background()); !res.Applied {
		t.Fatalf("not applied: %v", res.Diagnostics)
	}
	if len(seen) != 1 || seen[0] != l.Current() {
		t.Fatalf("hook calls %d", len(seen))
	}
	d.remove("realms/a.yaml") // the last realm: not applied
	if res := l.Reload(context.Background()); res.Applied {
		t.Fatal("applied without a realm")
	}
	if len(seen) != 1 {
		t.Fatalf("hook ran for a reload that was not applied")
	}
}

// LiveSecrets answers from the snapshot current at each call, so a key added
// by a reload is found by a service built before it.
func TestLiveSecretsFollowTheCurrentSnapshot(t *testing.T) {
	d := newCfgDir(t)
	d.realm("main", "Main", "")
	l, _, _ := d.loader(t)
	live := config.LiveSecrets{Source: l}
	if live.Signing("main-k1") == nil {
		t.Fatal("no signing key of main")
	}
	if live.Signing("second-k1") != nil {
		t.Fatal("a key that is not loaded")
	}
	d.realm("second", "Second", "")
	if res := l.Reload(context.Background()); !res.Applied {
		t.Fatalf("reload not applied: %v", res.Diagnostics)
	}
	if live.Signing("second-k1") == nil {
		t.Fatal("the key of the new realm is not found after the reload")
	}
	if got, want := len(live.EncryptionKeys()), len(l.Current().Secrets().EncryptionKeys()); got != want {
		t.Fatalf("%d encryption keys, want %d", got, want)
	}
	if live.AppleKey("main", "apple") != nil || live.ClientSecret("main", config.ClientSecretOf, "none") != "" {
		t.Fatal("secrets that do not exist")
	}
}

// A LiveSecrets logs only counts, directly and nested in a map, and never the
// key material it holds.
func TestLiveSecretsAreSafeToLog(t *testing.T) {
	d := newCfgDir(t)
	d.realm("main", "Main", "")
	l, _, _ := d.loader(t)
	live := config.LiveSecrets{Source: l}
	pemBytes, err := os.ReadFile(filepath.Join(d.root, "secrets", "main", "signing.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []string
	for _, line := range strings.Split(string(pemBytes), "\n") {
		if len(line) > 30 && !strings.HasPrefix(line, "-----") {
			fixtures = append(fixtures, line)
		}
	}
	if len(fixtures) == 0 {
		t.Fatal("no key material in the fixture")
	}
	for _, k := range live.EncryptionKeys() {
		fixtures = append(fixtures, base64.StdEncoding.EncodeToString(k))
	}
	var buf bytes.Buffer
	log := logx.New(&buf, slog.LevelDebug, newFake())
	log.Info("direct", "secrets", live)
	log.Info("nested", "details", map[string]any{"secrets": live})
	if !strings.Contains(buf.String(), "direct") || !strings.Contains(buf.String(), "nested") {
		t.Fatalf("nothing was logged: %q", buf.String())
	}
	for _, f := range fixtures {
		if strings.Contains(buf.String(), f) {
			t.Fatalf("the log holds key material:\n%s", buf.String())
		}
	}
}

// Covers: SEC-30
// Acceptance: Client secret length (part)
func TestShortClientSecretIsLoggedAtLoad(t *testing.T) {
	secret := "SENTINEL-" + strings.Repeat("y", 22) // 31 characters
	d := newCfgDir(t)
	d.realm("a", "A", "  api:\n    type: confidential\n    client_secret_file: secrets/a/api\n    redirect_uris: [https://api.example.com/cb]\n")
	d.write("secrets/a/api", secret+"\n", 0o600)
	_, _, logs := d.loader(t)
	out := logs.String()
	for _, want := range []string{
		`"msg":"configuration warning"`,
		`"field":"clients.api.client_secret_file"`,
		`"reason":"secret file secrets/a/api is shorter than 32 characters; use a client secret of at least 32 characters"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, secret) {
		t.Error("the secret reached the log")
	}
}
