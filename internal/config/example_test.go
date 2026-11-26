package config

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
)

func exampleFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/examples/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func loadDir(t *testing.T, d *configdir.Dir) (*Loader, []Diagnostic) {
	t.Helper()
	l, err := NewLoader(d.Root, clock.NewFake(time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	return l, l.Status().Last.Diagnostics
}

// compactDir writes the compact example of the design with the files it names.
func compactDir(t *testing.T) *configdir.Dir {
	t.Helper()
	d := configdir.New(t)
	d.Server(t, exampleFile(t, "compact-server.yaml"))
	d.Realm(t, "main", exampleFile(t, "compact-main.yaml"))
	d.RSAKey(t, "secrets/main/signing-2026-10.pem")
	d.Secret(t, "secrets/main/google_client_secret")
	return d
}

// keycloakDir writes the Keycloak migration files and the secrets they name.
// With apple, Apple is enabled and its four fields are filled in.
func keycloakDir(t *testing.T, apple bool) *configdir.Dir {
	t.Helper()
	d := configdir.New(t)
	d.Server(t, exampleFile(t, "keycloak-server.yaml"))
	realm := exampleFile(t, "keycloak-main.yaml")
	d.RSAKey(t, "secrets/main/signing-2026-11.pem")
	d.Secret(t, "secrets/main/google_client_secret")
	d.EncryptionKey(t, "secrets/encryption_key")
	if apple {
		const off = "  apple:\n    enabled: false"
		if strings.Count(realm, off) != 1 {
			t.Fatal("the apple block of the example changed")
		}
		realm = strings.Replace(realm, off, "  apple:\n    enabled: true\n"+
			"    client_id: com.example.signin\n    team_id: ABCDE12345\n"+
			"    key_id: ABC123DEFG\n    private_key_file: secrets/main/apple_key.p8", 1)
		d.AppleKey(t, "secrets/main/apple_key.p8")
	}
	d.Realm(t, "main", realm)
	return d
}

func warningFields(ds []Diagnostic) []string {
	var out []string
	for _, d := range ds {
		if d.Severity == Error {
			out = append(out, "ERROR "+d.String())
			continue
		}
		out = append(out, d.File+":"+d.Field)
	}
	slices.Sort(out)
	return out
}

// Covers: FR-19 (part)
func TestCompactExampleAppliesEveryDefault(t *testing.T) {
	l, ds := loadDir(t, compactDir(t))
	// The mobile client has a custom-scheme redirect URI while Google is on
	// and Apple is off, which is the Guideline 4.8 warning; nothing else.
	want := []string{"realms/main.yaml:clients.mobile.redirect_uris[0]"}
	if got := warningFields(ds); !slices.Equal(got, want) {
		t.Fatalf("diagnostics %v, want %v", got, want)
	}
	snap := l.Current()

	srv := snap.Server()
	wantSrv := defaultServer()
	wantSrv.PublicURL = "https://auth.example.com"
	srv.lines = nil
	if !reflect.DeepEqual(srv, wantSrv) {
		t.Errorf("server\n got %+v\nwant %+v", srv, wantSrv)
	}
	db := snap.Database()
	wantDB := defaultDatabase()
	db.lines = nil
	if !reflect.DeepEqual(db, wantDB) {
		t.Errorf("database\n got %+v\nwant %+v", db, wantDB)
	}

	r, ok := snap.Realm("main")
	if !ok || len(snap.Realms()) != 1 {
		t.Fatal("realm main missing")
	}
	def := defaultRealm()
	def.Tokens.Algorithm = "RS256"
	if r.DisplayName != "main" || !r.Enabled {
		t.Errorf("display name %q enabled %v", r.DisplayName, r.Enabled)
	}
	if r.Tokens != def.Tokens || !reflect.DeepEqual(r.UserData, def.UserData) ||
		!reflect.DeepEqual(r.LoginPage, def.LoginPage) || r.SecurityHeaders != def.SecurityHeaders {
		t.Errorf("realm defaults not applied: %+v", r)
	}
	wantKeys := []Key{{Kid: "main-2026-10", File: "secrets/main/signing-2026-10.pem", State: "active"}}
	if !reflect.DeepEqual(r.Keys, wantKeys) {
		t.Errorf("keys %+v", r.Keys)
	}

	wantG := defaultProvider("google", "google")
	wantG.Enabled, wantG.ClientID = true, "1234.apps.googleusercontent.com"
	wantG.ClientSecretFile = "secrets/main/google_client_secret"
	if len(r.Providers) != 1 || !reflect.DeepEqual(*r.Providers["google"], wantG) {
		t.Errorf("providers %+v", r.Providers)
	}

	web := defaultClient("web")
	web.RedirectURIs, web.WebOrigins = []string{"https://app.example.com/callback"}, []string{"https://app.example.com"}
	mobile := defaultClient("mobile")
	mobile.RedirectURIs = []string{"com.example.app:/callback"}
	idle, zero := Duration(17520*time.Hour), Duration(0)
	mobile.RefreshIdleLifetime, mobile.SessionMaxLifetime, mobile.AllowAccountDelete = &idle, &zero, true
	for id, want := range map[ClientID]Client{"web": web, "mobile": mobile} {
		got := *r.Clients[id]
		got.realm = nil
		if !reflect.DeepEqual(got, want) {
			t.Errorf("client %s\n got %+v\nwant %+v", id, got, want)
		}
	}
	if len(r.Clients) != 2 {
		t.Errorf("clients %v", r.Clients)
	}
	if r.Clients["mobile"].Lifetimes().RefreshIdle != 17520*time.Hour || r.Clients["web"].Lifetimes().RefreshIdle != 720*time.Hour {
		t.Error("lifetimes not resolved")
	}

	if got := r.Issuer(); got != "https://auth.example.com/main" {
		t.Errorf("issuer %q", got)
	}
	if got := r.EndpointURL(EndpointToken, ""); got != "https://auth.example.com/main/token" {
		t.Errorf("token endpoint %q", got)
	}
	if got := r.EndpointURL(EndpointCallback, "google"); got != "https://auth.example.com/main/callback/google" {
		t.Errorf("callback %q", got)
	}
	sec := snap.Secrets()
	if sec.Signing("main-2026-10") == nil || sec.ClientSecret("main", ProviderSecret, "google") == "" {
		t.Error("secrets not loaded")
	}
}

// Covers: FR-28 (part)
func TestKeycloakExampleWarnsAppleOffAndPKCE(t *testing.T) {
	l, ds := loadDir(t, keycloakDir(t, false))
	want := []string{
		"realms/main.yaml:clients.app.redirect_uris[0]", // App Store Review Guideline 4.8
		"realms/main.yaml:clients.app.require_pkce",
	}
	if got := warningFields(ds); !slices.Equal(got, want) {
		t.Fatalf("diagnostics %v, want %v", got, want)
	}
	checkKeycloakSnapshot(t, l.Current(), false)
}

// Covers: FR-28 (part)
func TestKeycloakExampleWithAppleWarnsOnlyPKCE(t *testing.T) {
	l, ds := loadDir(t, keycloakDir(t, true))
	want := []string{"realms/main.yaml:clients.app.require_pkce"}
	if got := warningFields(ds); !slices.Equal(got, want) {
		t.Fatalf("diagnostics %v, want %v", got, want)
	}
	checkKeycloakSnapshot(t, l.Current(), true)
}

func checkKeycloakSnapshot(t *testing.T, snap *Snapshot, apple bool) {
	t.Helper()
	r, ok := snap.Realm("main")
	if !ok {
		t.Fatal("realm main missing")
	}
	const base = "https://auth.example.com/auth/realms/main"
	for _, c := range []struct{ got, want string }{
		{r.Issuer(), base},
		{r.EndpointURL(EndpointAuthorize, ""), base + "/protocol/openid-connect/auth"},
		{r.EndpointURL(EndpointToken, ""), base + "/protocol/openid-connect/token"},
		{r.EndpointURL(EndpointUserinfo, ""), base + "/protocol/openid-connect/userinfo"},
		{r.EndpointURL(EndpointJWKS, ""), base + "/protocol/openid-connect/certs"},
		{r.EndpointURL(EndpointLogout, ""), base + "/protocol/openid-connect/logout"},
		{r.EndpointURL(EndpointCallback, "google"), base + "/broker/google/endpoint"},
		{r.EndpointURL(EndpointCallback, "apple"), base + "/broker/apple/endpoint"},
	} {
		if c.got != c.want {
			t.Errorf("got %q want %q", c.got, c.want)
		}
	}
	s := snap.Server()
	if !slices.Equal(s.Login.ProviderHintParams, []string{"provider", "kc_idp_hint"}) ||
		!slices.Equal(s.Logout.RedirectParams, []string{"post_logout_redirect_uri", "redirect_uri"}) {
		t.Errorf("login/logout params %v %v", s.Login.ProviderHintParams, s.Logout.RedirectParams)
	}
	if r.DisplayName != "Example app" || r.Tokens.RefreshTokenFormat != "jwt" ||
		r.Tokens.RefreshIdleLifetime.Std() != 30*time.Minute || r.Tokens.SessionMaxLifetime.Std() != 10*time.Hour ||
		r.Tokens.LoginTimeout.Std() != 30*time.Minute {
		t.Errorf("tokens %+v", r.Tokens)
	}
	cl := r.Clients["app"]
	if cl == nil || cl.RequirePKCE || cl.ResponseMode != "fragment" || cl.Audience != "account" || cl.Type != Public ||
		len(cl.RedirectURIs) != 3 || len(cl.PostLogoutURIs()) != 3 {
		t.Errorf("app %+v", cl)
	}
	g := r.Providers["google"]
	if g == nil || !g.Enabled || !g.TrustEmail || g.ClientSecretFile != "secrets/main/google_client_secret" {
		t.Errorf("google %+v", g)
	}
	if a := r.Providers["apple"]; a == nil || a.Enabled != apple {
		t.Errorf("apple %+v", a)
	}
	sec := snap.Secrets()
	if sec.Signing("main-2026-11") == nil || len(sec.EncryptionKeys()) != 1 ||
		sec.ClientSecret("main", ProviderSecret, "google") == "" {
		t.Error("secrets not loaded")
	}
	if apple && sec.AppleKey("main", "apple") == nil {
		t.Error("apple key not loaded")
	}
}

// Covers: FR-19 (part)
func TestEveryDocumentedOptionIsReachableFromSnapshot(t *testing.T) {
	d := configdir.New(t)
	d.Server(t, "public_url: https://auth.example.com\n")
	d.RSAKey(t, "secrets/all/signing.pem")
	d.Realm(t, "all", `name: all
keys:
  - { kid: all-1, file: secrets/all/signing.pem, state: active }
providers:
  google: {}
  apple: {}
  github: {}
  facebook: {}
  oidc: {}
clients:
  web:
    redirect_uris: [https://app.example.com/callback]
`)
	l, ds := loadDir(t, d)
	if len(ds) != 0 {
		t.Fatalf("diagnostics %v", ds)
	}
	snap := l.Current()
	realm, _ := snap.Realm("all")
	srv, db := snap.Server(), snap.Database()
	tables := designTables(t)

	roots := map[string]reflect.Type{
		"server": reflect.TypeOf(srv), "database": reflect.TypeOf(db),
		"client": reflect.TypeOf(*realm.Clients["web"]), "common": reflect.TypeOf(*realm.Providers["google"]),
	}
	n := 0
	check := func(section string, typ reflect.Type, opts []string) {
		for _, o := range opts {
			n++
			if _, _, ok := field(typ, o); !ok {
				t.Errorf("%s option %q is not reachable from the snapshot", section, o)
			}
		}
	}
	for section, typ := range roots {
		for _, row := range tables[section] {
			check(section, typ, row.options)
		}
	}
	for _, row := range tables["per-provider"] {
		p, ok := realm.Providers[ProviderKey(row.provider)]
		if !ok {
			t.Errorf("provider %q is not in the snapshot", row.provider)
			continue
		}
		check(row.provider, reflect.TypeOf(*p), row.options)
	}
	// Realm options: the snapshot's Realm has the same fields as the file.
	rt := reflect.TypeOf(*realm)
	for _, row := range tables["realm"] {
		for _, o := range row.options {
			n++
			first, rest, _ := strings.Cut(o, ".")
			first = strings.TrimSuffix(first, "[]")
			sf, _, ok := field(reflect.TypeOf(RealmFile{}), first)
			if !ok {
				t.Errorf("realm option %q is unknown", o)
				continue
			}
			rsf, ok := rt.FieldByName(sf.Name)
			if !ok {
				t.Errorf("realm option %q: Realm has no field %s", o, sf.Name)
				continue
			}
			if rest != "" {
				if _, _, ok := field(rsf.Type, rest); !ok {
					t.Errorf("realm option %q is not reachable from the snapshot", o)
				}
			}
		}
	}
	if n < 100 {
		t.Errorf("only %d options checked; the design tables were not read", n)
	}
}
