package config

import (
	"reflect"
	"testing"
	"time"
)

// Covers: FR-19 (part)
// Acceptance: Config remarks (part)
func TestSecondYAMLDocumentIsAnError(t *testing.T) {
	doc := "name: main\n---\nname: other\n"
	for _, kind := range []string{"server", "database", "realm"} {
		t.Run(kind, func(t *testing.T) {
			var ds []Diagnostic
			switch kind {
			case "server":
				_, ds = DecodeServer("f.yaml", []byte("public_url: https://a.example\n---\npublic_url: https://b.example\n"))
			case "database":
				_, ds = DecodeDatabase("f.yaml", []byte("sqlite:\n  path: /x\n---\nsqlite:\n  path: /y\n"))
			default:
				_, ds = DecodeRealm("f.yaml", []byte(doc))
			}
			n := 0
			for _, d := range ds {
				if d.Severity == Error && d.File == "f.yaml" && d.Line > 0 && d.Message != "" {
					n++
					want := map[string]int{"server": 3, "database": 4, "realm": 3}[kind]
					if d.Line != want {
						t.Errorf("line %d, want %d", d.Line, want)
					}
				}
			}
			if n != 1 {
				t.Fatalf("want one error diagnostic, got %v", ds)
			}
		})
	}
}

// Covers: FR-19 (part)
// Acceptance: Config remarks (part)
func TestUnknownFieldReportsFileLineAndFieldPath(t *testing.T) {
	tests := []struct {
		name  string
		kind  string
		doc   string
		line  int
		field string
	}{
		{"server top level", "server", "public_url: https://a.example\nbogus: 1\n", 2, "bogus"},
		{"server nested", "server", "rate_limit:\n  per_ip_per_minut: 3\n", 2, "rate_limit.per_ip_per_minut"},
		{"server endpoint", "server", "urls:\n  endpoints:\n    authorise: /x\n", 3, "urls.endpoints.authorise"},
		{"database nested", "database", "sqlite:\n  path: /x\n  pathh: /y\n", 3, "sqlite.pathh"},
		{"realm top level", "realm", "name: main\n\nenabeld: true\n", 3, "enabeld"},
		{"realm nested", "realm", "name: main\ntokens:\n  access_token_lifetim: 1m\n", 3, "tokens.access_token_lifetim"},
		{"realm list item", "realm", "keys:\n  - kid: a\n    fil: x\n", 3, "keys[0].fil"},
		{"realm provider", "realm", "providers:\n  google:\n    hosted_domainn: x\n", 3, "providers.google.hosted_domainn"},
		{"provider option of another type", "realm", "providers:\n  github:\n    hosted_domain: x\n", 3, "providers.github.hosted_domain"},
		{"provider type from field", "realm", "providers:\n  corp:\n    type: oidc\n    hosted_domain: x\n", 4, "providers.corp.hosted_domain"},
		{"provider endpoints", "realm", "providers:\n  google:\n    endpoints:\n      tokn: x\n", 4, "providers.google.endpoints.tokn"},
		{"client", "realm", "clients:\n  web:\n    redirect_uri: [x]\n", 3, "clients.web.redirect_uri"},
		{"flow style", "realm", "keys: [{kid: a, filee: x}]\n", 1, "keys[0].filee"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ds []Diagnostic
			switch tc.kind {
			case "server":
				_, ds = DecodeServer("server.yaml", []byte(tc.doc))
			case "database":
				_, ds = DecodeDatabase("database.yaml", []byte(tc.doc))
			default:
				_, ds = DecodeRealm("realms/main.yaml", []byte(tc.doc))
			}
			if len(ds) != 1 {
				t.Fatalf("want one diagnostic, got %v", ds)
			}
			d := ds[0]
			if d.File != map[string]string{"server": "server.yaml", "database": "database.yaml", "realm": "realms/main.yaml"}[tc.kind] ||
				d.Line != tc.line || d.Field != tc.field || d.Severity != Error || d.Message == "" {
				t.Fatalf("got %+v, want line %d field %q error", d, tc.line, tc.field)
			}
		})
	}
}

// Covers: FR-19 (part)
func TestKnownFieldsOfEveryTypeAreAccepted(t *testing.T) {
	const doc = `
name: main
display_name: Main
enabled: false
tokens: {access_token_lifetime: 5m, refresh_idle_lifetime: 1h, session_max_lifetime: 0, code_lifetime: 30s, login_timeout: 1m, refresh_reuse_grace: 0s, refresh_token_rotation: false, account_delete_max_auth_age: 1m, algorithm: ES256, refresh_token_format: jwt}
keys:
  - {kid: a, file: a.pem, state: active}
user_data: {attributes: [email], claims: [name], keep_name_if_missing: false, id_format: ulid, auto_link_domains: [x.com]}
login_page: {logo_url: "https://x/l.png", accent_color: "#fff", contact: a@b.c, provider_order: [apple], default_locale: de, supported_locales: [en, de]}
security_headers: {content_security_policy: "", hsts: ""}
providers:
  google: {enabled: true, hosted_domain: x.com, client_id: i, client_secret_file: s, scopes: [openid], trust_email: false, auto_link: false, sync_mode: force, timeout: 5s, hidden: true, display_name: G}
  apple: {team_id: t, key_id: k, private_key_file: p, client_secret_lifetime: 1h, store_refresh_token: false, notification_audiences: [x]}
  github: {pkce: false, allow_signup: false, require_verified_email: false}
  facebook: {graph_version: v1.0, flow: oauth, fields: [id], require_email: true}
  corp: {type: oidc, issuer: "https://i", endpoints: {authorize: a, token: b, userinfo: c, jwks: d}}
clients:
  web: {name: W, description: d, type: confidential, client_secret_file: s, redirect_uris: [x], post_logout_redirect_uris: [y], web_origins: [z], require_pkce: false, response_mode: fragment, audience: api, access_token_lifetime: 1m, refresh_idle_lifetime: 2m, session_max_lifetime: 0, refresh_token_rotation: false, allow_account_delete: true}
`
	r, ds := DecodeRealm("main.yaml", []byte(doc))
	if len(ds) != 0 {
		t.Fatalf("diagnostics: %v", ds)
	}
	if r.Tokens.AccessTokenLifetime.Std() != 5*time.Minute || r.Tokens.SessionMaxLifetime != 0 {
		t.Fatalf("tokens not decoded: %+v", r.Tokens)
	}
	g := r.Providers["google"]
	if g.HostedDomain != "x.com" || g.TrustEmail || g.Timeout.Std() != 5*time.Second || g.Type != "google" {
		t.Fatalf("google not decoded: %+v", g)
	}
	if r.Providers["corp"].Issuer != "https://i" {
		t.Fatal("oidc options not decoded")
	}
	c := r.Clients["web"]
	if c.Type != Confidential || c.RefreshTokenRotation == nil || *c.RefreshTokenRotation ||
		c.SessionMaxLifetime == nil || *c.SessionMaxLifetime != 0 || c.AccessTokenLifetime == nil {
		t.Fatalf("client not decoded: %+v", c)
	}
}

func TestExplicitValuesReplaceDefaultLists(t *testing.T) {
	r, ds := DecodeRealm("main.yaml", []byte("user_data:\n  claims: []\n  attributes: [email]\n"))
	if len(ds) != 0 {
		t.Fatal(ds)
	}
	if len(r.UserData.Claims) != 0 || !reflect.DeepEqual(r.UserData.Attributes, []string{"email"}) {
		t.Fatalf("got %+v", r.UserData)
	}
}

func TestDefaultsSpotChecks(t *testing.T) {
	s, ds := DecodeServer("server.yaml", nil)
	if len(ds) != 0 {
		t.Fatal(ds)
	}
	if s.Listen != ":8080" || !s.RequireHTTPS || s.RateLimit.PerIPPerMinute != 30 ||
		s.URLs.Endpoints.Callback != "{prefix}/{realm}/callback/{provider}" ||
		!reflect.DeepEqual(s.Secrets.EncryptionKeyFiles, []string{"secrets/encryption_key"}) ||
		!reflect.DeepEqual(s.Login.ProviderHintParams, []string{"provider"}) {
		t.Fatalf("server defaults: %+v", s)
	}
	d, ds := DecodeDatabase("database.yaml", []byte(""))
	if len(ds) != 0 {
		t.Fatal(ds)
	}
	if d.Driver != "sqlite" || d.SQLite.BusyTimeout.Std() != 5*time.Second || d.SQLite.ReadConnections != 4 ||
		d.Backup.At != "03:00" || d.Backup.Keep != 7 || d.Postgres.Port != 5432 || d.Postgres.ConnMaxLifetime.Std() != 30*time.Minute ||
		d.Postgres.ConnectTimeout.Std() != 5*time.Second {
		t.Fatalf("database defaults: %+v", d)
	}
	r, ds := DecodeRealm("main.yaml", []byte("name: main\nproviders:\n  google: {}\n  facebook: {}\n  apple: {}\n  github: {}\nclients:\n  web: {}\n"))
	if len(ds) != 0 {
		t.Fatal(ds)
	}
	if r.DisplayName != "main" || !r.Enabled || r.Tokens.AccessTokenLifetime.Std() != 15*time.Minute ||
		r.Tokens.SessionMaxLifetime.Std() != 2160*time.Hour || r.Tokens.RefreshReuseGrace.Std() != 30*time.Second {
		t.Fatalf("realm defaults: %+v", r)
	}
	if !r.Providers["google"].TrustEmail || r.Providers["facebook"].TrustEmail ||
		!reflect.DeepEqual(r.Providers["apple"].Scopes, []string{"name", "email"}) ||
		r.Providers["apple"].ClientSecretLifetime.Std() != 5*time.Minute ||
		r.Providers["github"].Type != "github" || r.Providers["github"].DisplayName != "GitHub" ||
		r.Providers["github"].Enabled || !r.Providers["github"].PKCE {
		t.Fatalf("provider defaults: %+v", r.Providers)
	}
	c := r.Clients["web"]
	if c.Name != "web" || c.Audience != "web" || c.Type != Public || !c.RequirePKCE || c.ResponseMode != "query" ||
		c.AccessTokenLifetime != nil || c.RefreshTokenRotation != nil || c.AllowAccountDelete {
		t.Fatalf("client defaults: %+v", c)
	}
}

// Covers: FR-25 (part)
func TestDatabaseSettingsOnlyFromDatabaseYAML(t *testing.T) {
	for _, doc := range []string{"driver: sqlite\n", "sqlite:\n  path: /x\n", "postgres: {host: h}\n", "backup: {keep: 3}\n", "database: {driver: sqlite}\n"} {
		_, ds := DecodeServer("server.yaml", []byte(doc))
		if len(ds) != 1 || ds[0].Severity != Error {
			t.Errorf("server.yaml accepted %q: %v", doc, ds)
		}
		_, ds = DecodeRealm("main.yaml", []byte(doc))
		if len(ds) != 1 || ds[0].Severity != Error {
			t.Errorf("realm file accepted %q: %v", doc, ds)
		}
	}
	d, ds := DecodeDatabase("database.yaml", []byte("driver: postgres\nsqlite: {path: /x.db}\nbackup: {keep: 3}\n"))
	if len(ds) != 0 || d.Driver != "postgres" || d.SQLite.Path != "/x.db" || d.Backup.Keep != 3 {
		t.Fatalf("database.yaml: %+v %v", d, ds)
	}
}

func TestDecodeProblems(t *testing.T) {
	tests := []struct {
		name  string
		doc   string
		line  int
		field string
	}{
		{"bad duration", "name: m\ntokens:\n  code_lifetime: soon\n", 3, "tokens.code_lifetime"},
		{"duration without unit", "tokens:\n  code_lifetime: 30\n", 2, "tokens.code_lifetime"},
		{"wrong scalar type", "enabled: perhaps\n", 1, "enabled"},
		{"wrong list type", "keys: nope\n", 1, "keys"},
		{"duplicate key", "name: a\nname: b\n", 2, "name"},
		{"syntax", "name: [a\n", 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ds := DecodeRealm("main.yaml", []byte(tc.doc))
			if len(ds) == 0 {
				t.Fatal("no diagnostic")
			}
			d := ds[0]
			if d.Severity != Error || d.File != "main.yaml" || d.Message == "" {
				t.Fatalf("got %+v", d)
			}
			if tc.line != 0 && (d.Line != tc.line || d.Field != tc.field) {
				t.Fatalf("got line %d field %q, want %d %q", d.Line, d.Field, tc.line, tc.field)
			}
		})
	}
}

func TestDurationParsing(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"30s", 30 * time.Second, true},
		{"15m", 15 * time.Minute, true},
		{"720h", 720 * time.Hour, true},
		{"1h30m", 90 * time.Minute, true},
		{"0", 0, true},
		{"0s", 0, true},
		{"-5s", -5 * time.Second, true},
		{"30", 0, false},
		{"soon", 0, false},
		{"", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			d, err := ParseDuration(tc.in)
			if (err == nil) != tc.ok || (tc.ok && d.Std() != tc.want) {
				t.Fatalf("ParseDuration(%q) = %v, %v", tc.in, d, err)
			}
		})
	}
}

func TestRealmFileLine(t *testing.T) {
	r, _ := DecodeRealm("main.yaml", []byte("name: main\ntokens:\n  code_lifetime: 1m\nkeys:\n  - kid: a\n"))
	for field, want := range map[string]int{"name": 1, "tokens.code_lifetime": 3, "keys[0].kid": 5, "missing": 0} {
		if got := r.Line(field); got != want {
			t.Errorf("Line(%q) = %d, want %d", field, got, want)
		}
	}
}

func TestSpecialYAMLDoesNotBreakDecoding(t *testing.T) {
	docs := []string{
		"a: &x {kid: k}\nkeys: [*x]\n",
		"base: &b {kid: k}\nkeys:\n  - <<: *b\n    file: f\n",
		"keys:\n  - <<: {kid: k, bogus: 1}\n",
		"---\nname: a\n---\nname: b\n",
		"- a\n- b\n",
		"null\n",
		"~\n",
		"tokens: ~\n",
		"providers: ~\nclients: [a]\n",
	}
	for _, doc := range docs {
		r, ds := DecodeRealm("main.yaml", []byte(doc))
		if r == nil && len(ds) == 0 {
			t.Errorf("%q: neither result nor diagnostic", doc)
		}
	}
}

// FuzzDecodeRealm: decoding any input never panics and yields a file or a diagnostic.
func FuzzDecodeRealm(f *testing.F) {
	seeds := []string{
		"",
		"name: main\n",
		"name: main\ntokens:\n  access_token_lifetime: 15m\nkeys:\n  - {kid: a, file: a.pem, state: active}\n",
		"providers:\n  google: {enabled: true}\n  corp: {type: oidc, issuer: https://x}\nclients:\n  web: {redirect_uris: [https://a/cb]}\n",
		"bogus: 1\n",
		"tokens:\n  code_lifetime: soon\n",
		"name: [a\n",
		"a: &x {kid: k}\nkeys: [*x]\n",
		"base: &b {kid: k}\nkeys:\n  - <<: *b\n",
		"---\na: 1\n---\nb: 2\n",
		"- a\n- b\n",
		"providers: ~\nclients: [a]\n",
		"\x00\xff",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, ds := DecodeRealm("main.yaml", b)
		if r == nil && len(ds) == 0 {
			t.Fatal("neither result nor diagnostic")
		}
	})
}

func TestDiagnosticAndSeverityText(t *testing.T) {
	if Error.String() != "error" || Warning.String() != "warning" || Severity(0).String() != "unknown" {
		t.Fatal("severity text")
	}
	tests := []struct {
		d    Diagnostic
		want string
	}{
		{Diagnostic{File: "a.yaml", Line: 3, Field: "x.y", Severity: Error, Message: "bad"}, "a.yaml:3: error: x.y: bad"},
		{Diagnostic{File: "a.yaml", Severity: Warning, Message: "odd"}, "a.yaml: warning: odd"},
	}
	for _, tc := range tests {
		if got := tc.d.String(); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
	if Duration(90*time.Second).String() != "1m30s" {
		t.Fatal("duration text")
	}
}

func TestInvalidYAMLGivesNoFile(t *testing.T) {
	if s, ds := DecodeServer("server.yaml", []byte("a: [b\n")); s != nil || len(ds) != 1 || ds[0].Line == 0 {
		t.Errorf("server: %v %v", s, ds)
	}
	if d, ds := DecodeDatabase("database.yaml", []byte("a: [b\n")); d != nil || len(ds) != 1 {
		t.Errorf("database: %v %v", d, ds)
	}
	if r, ds := DecodeRealm("main.yaml", []byte("a: [b\n")); r != nil || len(ds) != 1 || ds[0].Severity != Error {
		t.Errorf("realm: %v %v", r, ds)
	}
}

func TestProvidersAndClientsEdgeCases(t *testing.T) {
	t.Run("null entries get defaults", func(t *testing.T) {
		r, ds := DecodeRealm("main.yaml", []byte("providers:\n  github:\nclients:\n  web:\n"))
		if len(ds) != 0 || r.Providers["github"] == nil || !r.Providers["github"].PKCE || r.Clients["web"] == nil || r.Clients["web"].Audience != "web" {
			t.Fatalf("%+v %v", r, ds)
		}
	})
	t.Run("unknown type accepts every option", func(t *testing.T) {
		r, ds := DecodeRealm("main.yaml", []byte("providers:\n  mycorp: {hosted_domain: x, issuer: y}\n"))
		if len(ds) != 0 || r.Providers["mycorp"].Type != "mycorp" {
			t.Fatalf("%+v %v", r.Providers, ds)
		}
	})
	t.Run("providers must be a mapping", func(t *testing.T) {
		_, ds := DecodeRealm("main.yaml", []byte("providers: [a]\n"))
		if len(ds) != 1 || ds[0].Line != 1 {
			t.Fatal(ds)
		}
	})
	t.Run("duplicate provider key", func(t *testing.T) {
		_, ds := DecodeRealm("main.yaml", []byte("providers:\n  google: {}\n  google: {}\n"))
		if len(ds) == 0 || ds[0].Line != 3 {
			t.Fatal(ds)
		}
	})
	t.Run("type error inside a provider", func(t *testing.T) {
		_, ds := DecodeRealm("main.yaml", []byte("providers:\n  google:\n    timeout: soon\n    enabled: maybe\n"))
		if len(ds) != 2 || ds[0].Field != "providers.google.timeout" || ds[1].Field != "providers.google.enabled" {
			t.Fatal(ds)
		}
	})
	t.Run("provider key that is not text", func(t *testing.T) {
		_, ds := DecodeRealm("main.yaml", []byte("providers:\n  ? [a]\n  : {}\n"))
		if len(ds) == 0 {
			t.Fatal("no diagnostic")
		}
	})
	t.Run("duration that is not text", func(t *testing.T) {
		_, ds := DecodeRealm("main.yaml", []byte("tokens:\n  code_lifetime: [1]\n"))
		if len(ds) != 1 || ds[0].Field != "tokens.code_lifetime" {
			t.Fatal(ds)
		}
	})
	t.Run("not a mapping at the top", func(t *testing.T) {
		s, ds := DecodeServer("server.yaml", []byte("- a\n"))
		if s == nil || len(ds) != 1 || ds[0].Line != 1 {
			t.Fatal(ds)
		}
	})
	t.Run("merge keys, including a list of maps", func(t *testing.T) {
		doc := "a: &a {kid: k1}\nb: &b {file: f}\nkeys:\n  - <<: [*a, *b]\n    state: active\n"
		_, ds := DecodeRealm("main.yaml", []byte(doc))
		// a and b are not realm options
		if len(ds) != 2 {
			t.Fatal(ds)
		}
		r, ds := DecodeRealm("main.yaml", []byte("keys:\n  - <<: [{kid: k1}, {file: f}]\n    state: active\n"))
		if len(ds) != 0 || r.Keys[0].Kid != "k1" || r.Keys[0].File != "f" {
			t.Fatalf("%+v %v", r.Keys, ds)
		}
	})
}

// Covers: FR-14 (part)
// Acceptance: Provider config (part)
func TestGenericOIDCDefaultScopes(t *testing.T) {
	r, ds := DecodeRealm("main.yaml", []byte("name: main\nproviders:\n  corp: {type: oidc, issuer: \"https://i\"}\n  other: {type: oidc, issuer: \"https://j\", scopes: [openid]}\n"))
	if len(ds) != 0 {
		t.Fatal(ds)
	}
	if got := r.Providers["corp"].Scopes; !reflect.DeepEqual(got, []string{"openid", "email", "profile"}) {
		t.Errorf("default scopes of a generic oidc provider = %v", got)
	}
	if got := r.Providers["other"].Scopes; !reflect.DeepEqual(got, []string{"openid"}) {
		t.Errorf("configured scopes = %v", got)
	}
}

// Covers: FR-22 (part)
func TestIDFormatDefaultAndExplicit(t *testing.T) {
	for _, tc := range []struct{ name, doc, want string }{
		{"default", "name: main\n", "uuid"},
		{"ulid", "user_data:\n  id_format: ulid\n", "ulid"},
		{"uuid", "user_data:\n  id_format: uuid\n", "uuid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, ds := DecodeRealm("main.yaml", []byte(tc.doc))
			if len(ds) != 0 {
				t.Fatal(ds)
			}
			if r.UserData.IDFormat != tc.want {
				t.Fatalf("IDFormat = %q, want %q", r.UserData.IDFormat, tc.want)
			}
		})
	}
}

// Covers: FR-04 (part)
// Acceptance: Provider buttons (part)
func TestDefaultProviderButtonText(t *testing.T) {
	for _, tc := range []struct{ name, typ, key, want string }{
		{"google", "google", "google", "Google"},
		{"apple", "apple", "apple", "Apple"},
		{"github", "github", "github", "GitHub"},
		{"facebook", "facebook", "facebook", "Facebook"},
		{"generic provider keeps its key", "oidc", "corp", "corp"},
		{"built-in adapter under another key", "google", "google-work", "Google"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultProvider(tc.typ, tc.key).DisplayName; got != tc.want {
				t.Errorf("default display_name of %s under %q = %q, want %q", tc.typ, tc.key, got, tc.want)
			}
		})
	}
}

// Covers: FR-48 (part)
// Acceptance: Google security events (part)
func TestRISCConfigurationIsGoogleOnly(t *testing.T) {
	const doc = `
providers:
  google:
    endpoints: {risc_configuration: "https://risc.example/.well-known/risc-configuration"}
`
	r, ds := DecodeRealm("main.yaml", []byte(doc))
	if len(ds) != 0 {
		t.Fatalf("google: diagnostics %v", ds)
	}
	if got := r.Providers["google"].Endpoints.RISCConfiguration; got != "https://risc.example/.well-known/risc-configuration" {
		t.Fatalf("risc_configuration = %q", got)
	}
	const other = `
providers:
  apple:
    endpoints: {risc_configuration: "https://risc.example/config"}
`
	_, ds = DecodeRealm("main.yaml", []byte(other))
	if len(ds) != 1 || ds[0].Field != "providers.apple.endpoints.risc_configuration" || ds[0].Message != "unknown field" {
		t.Fatalf("apple: diagnostics %v, want one unknown field", ds)
	}
}
