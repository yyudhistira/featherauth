package config

import (
	"net/url"
	"strings"
	"testing"
)

// Covers: FR-32 (part), SEC-02 (part)
// Acceptance: Config validation (part)
func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		typ  ClientType
		msg  string // a part of the reason; empty when the URI is accepted
	}{
		{"https", "https://app.example.com/callback", Public, ""},
		{"https with port and query", "https://app.example.com:8443/cb?x=1", Confidential, ""},
		{"custom scheme", "com.example.app:/callback", Public, ""},
		{"custom scheme on a confidential client", "com.example.app:/callback", Confidential, ""},
		{"loopback IPv4 for a public client", "http://127.0.0.1:8080/callback", Public, ""},
		{"loopback IPv4 without port", "http://127.0.0.1/callback", Public, ""},
		{"loopback IPv6 for a public client", "http://[::1]:8080/callback", Public, ""},

		{"empty", "", Public, "empty"},
		{"no scheme", "app.example.com/cb", Public, "absolute"},
		{"relative path", "/cb", Public, "absolute"},
		{"unparsable", "https://app example.com/cb", Public, "not a valid URI"},
		{"fragment", "https://app.example.com/cb#frag", Public, "fragment"},
		{"empty fragment", "https://app.example.com/cb#", Public, "fragment"},
		{"wildcard in the host", "https://*.example.com/cb", Public, "wildcard"},
		{"wildcard in the path", "https://app.example.com/*", Public, "wildcard"},
		{"wildcard in the query", "https://app.example.com/cb?x=*", Public, "wildcard"},
		{"javascript", "javascript:alert(1)", Public, "javascript"},
		{"javascript upper case", "JavaScript:alert(1)", Public, "javascript"},
		{"data", "data:text/html,x", Public, "data"},
		{"file", "file:///etc/passwd", Public, "file"},
		{"http on a public host", "http://app.example.com/cb", Public, "127.0.0.1"},
		{"http on a public host, confidential", "http://app.example.com/cb", Confidential, "127.0.0.1"},
		{"http localhost", "http://localhost:3000/cb", Public, "use http://127.0.0.1"},
		{"http LOCALHOST", "http://LOCALHOST:3000/cb", Public, "use http://127.0.0.1"},
		{"http mixed-case localhost", "http://LocalHost/cb", Confidential, "use http://127.0.0.1"},
		{"http localhost, confidential", "http://localhost/cb", Confidential, "use http://127.0.0.1"},
		{"http host that starts like loopback", "http://127.0.0.1.evil.example/cb", Public, "127.0.0.1"},
		{"http loopback as user info", "http://127.0.0.1@evil.example/cb", Public, "127.0.0.1"},
		{"https without a host", "https:///cb", Public, "host"},
		{"loopback IPv4 on a confidential client", "http://127.0.0.1:8080/cb", Confidential, "loopback"},
		{"loopback IPv6 on a confidential client", "http://[::1]:8080/cb", Confidential, "loopback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := ValidateRedirectURI(tt.raw, tt.typ)
			if tt.msg == "" {
				if d != nil {
					t.Fatalf("want accepted, got %+v", *d)
				}
				return
			}
			if d == nil {
				t.Fatalf("want a diagnostic containing %q, got none", tt.msg)
			}
			if d.Severity != Error || !strings.Contains(d.Message, tt.msg) {
				t.Fatalf("got %+v, want an error containing %q", *d, tt.msg)
			}
			if d.File != "" || d.Line != 0 || d.Field != "" {
				t.Fatalf("the caller places the diagnostic, got %+v", *d)
			}
		})
	}
}

// Covers: FR-32 (part), SEC-02 (part)
// Acceptance: Config validation (part)
func TestValidateWebOrigin(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		msg  string
	}{
		{"https", "https://app.example.com", ""},
		{"with port", "https://app.example.com:8443", ""},
		{"http loopback", "http://localhost:3000", ""},
		{"empty", "", "empty"},
		{"no scheme", "app.example.com", "origin"},
		{"path", "https://app.example.com/app", "origin"},
		{"trailing slash", "https://app.example.com/", "origin"},
		{"query", "https://app.example.com?x=1", "origin"},
		{"fragment", "https://app.example.com#x", "origin"},
		{"user info", "https://u@app.example.com", "origin"},
		{"wildcard host", "https://*.example.com", "wildcard"},
		{"star", "*", "wildcard"},
		{"unparsable", "https://app example.com", "not a valid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := ValidateWebOrigin(tt.raw)
			switch {
			case tt.msg == "" && d != nil:
				t.Fatalf("want accepted, got %+v", *d)
			case tt.msg != "" && (d == nil || d.Severity != Error || !strings.Contains(d.Message, tt.msg)):
				t.Fatalf("want an error containing %q, got %v", tt.msg, d)
			}
		})
	}
}

// Covers: FR-32 (part), SEC-02 (part)
// Acceptance: Config validation (part)
func FuzzValidateRedirectURI(f *testing.F) {
	for _, s := range []string{
		"", "https://app.example.com/cb", "com.example.app:/callback", "http://127.0.0.1:8080/cb",
		"http://[::1]:1/cb", "http://localhost/cb", "https://a/b#c", "https://*.a/", "javascript:alert(1)",
		"data:,x", "file:///x", "HTTP://127.0.0.1", "https://a.example?", "https://a.example/%7e", "https://a%2eexample/",
		"http://127.0.0.1@evil/", "a:b", "://", "https:///", "x\x00y:z", "https://a b/",
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, raw string, confidential bool) {
		typ := Public
		if confidential {
			typ = Confidential
		}
		d := ValidateRedirectURI(raw, typ)
		if d != nil {
			if d.Severity != Error || d.Message == "" {
				t.Fatalf("bad diagnostic %+v for %q", *d, raw)
			}
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("accepted %q, which does not parse: %v", raw, err)
		}
		// The canonical form of an accepted URI parses back to itself and is
		// accepted too. (Raw equality does not hold for every accepted URI:
		// url.Parse lower-cases the scheme, so HTTP://127.0.0.1 is accepted.)
		canon := u.String()
		u2, err := url.Parse(canon)
		if err != nil || u2.String() != canon {
			t.Fatalf("accepted %q, whose form %q does not parse back to itself", raw, canon)
		}
		if d := ValidateRedirectURI(canon, typ); d != nil {
			t.Fatalf("accepted %q but rejected its canonical form %q: %s", raw, canon, d.Message)
		}
		if u.Fragment != "" || strings.Contains(raw, "*") || strings.Contains(raw, "#") {
			t.Fatalf("accepted %q with a fragment or a wildcard", raw)
		}
	})
}

func FuzzValidateWebOrigin(f *testing.F) {
	for _, s := range []string{"", "https://a.example", "https://a.example/", "*", "https://*.a", "a:b", "https://a.example:8080", "A://0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if d := ValidateWebOrigin(raw); d == nil {
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" {
				t.Fatalf("accepted %q", raw)
			}
		}
	})
}

// Covers: FR-19 (part)
// Acceptance: iOS login rule
func TestIOSLoginRule(t *testing.T) {
	dir := keyDir(t)
	const app = "clients:\n  ios:\n    redirect_uris: [\"com.example.app:/cb\"]\n"
	prov := func(key, opts string) string { return "  " + key + ":\n" + opts }
	tests := []struct {
		name      string
		providers string
		clients   string
		warn      bool
	}{
		{"Google, no Apple", prov("google", googleOpts), app, true},
		{"GitHub, no Apple", prov("github", googleOpts), app, true},
		{"Facebook, no Apple", prov("facebook", facebookOpts), app + contactLine, true},
		{"Google, Apple disabled", prov("google", googleOpts) + prov("apple", "    enabled: false\n"), app, true},
		{"Google, Apple hidden", prov("google", googleOpts) + prov("apple", appleOpts+"    hidden: true\n"), app, true},
		{"Google, Apple enabled", prov("google", googleOpts) + prov("apple", appleOpts), app, false},
		{"Google, Apple under another key", prov("google", googleOpts) + prov("ios", "    type: apple\n"+appleOpts), app, false},
		{"Google disabled", prov("google", "    enabled: false\n"), app, false},
		{"Apple only", prov("apple", appleOpts), app, false},
		{"generic oidc only", prov("oidc", "    issuer: https://idp.example.com\n"+googleOpts), app, false},
		{"https redirect only", prov("google", googleOpts), "clients:\n  web:\n    redirect_uris: [\"https://app.example.com/cb\"]\n", false},
		{"loopback redirect only", prov("google", googleOpts), "clients:\n  desktop:\n    redirect_uris: [\"http://127.0.0.1:8080/cb\"]\n", false},
		{"confidential client with a custom scheme", prov("google", googleOpts), "clients:\n  bff:\n    type: confidential\n    client_secret_file: secrets/bff\n    redirect_uris: [\"com.example.app:/cb\"]\n", false},
		{"custom scheme in post-logout URIs only", prov("google", googleOpts), "clients:\n  web:\n    redirect_uris: [\"https://app.example.com/cb\"]\n    post_logout_redirect_uris: [\"com.example.app:/bye\"]\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := realmHead + "providers:\n" + tt.providers + tt.clients + realmKeys
			ds := validateText(t, dir, "realm", "realms/main.yaml", y, false)
			if !tt.warn {
				noErrors(t, ds)
				return
			}
			if len(ds) != 1 || ds[0].Severity != Warning || !strings.Contains(ds[0].Message, "App Store Review Guideline 4.8") ||
				ds[0].Field != "clients.ios.redirect_uris[0]" || ds[0].File != "realms/main.yaml" || ds[0].Line == 0 {
				t.Fatalf("got %v", ds)
			}
		})
	}
	// One warning for the realm however many clients and providers match.
	y := realmHead + "providers:\n" + prov("google", googleOpts) + prov("github", googleOpts) +
		"clients:\n  a:\n    redirect_uris: [\"com.example.a:/cb\", \"com.example.a2:/cb\"]\n  b:\n    redirect_uris: [\"com.example.b:/cb\"]\n" + realmKeys
	if ds := validateText(t, dir, "realm", "realms/main.yaml", y, false); len(ds) != 1 || ds[0].Field != "clients.a.redirect_uris[0]" {
		t.Fatalf("got %v", ds)
	}
}

// Covers: FR-32 (part)
// Acceptance: Rotation off (part)
func TestRotationOffIsAcceptedForConfidentialClients(t *testing.T) {
	dir := keyDir(t)
	for _, extra := range []string{"    refresh_token_rotation: false\n", "    refresh_token_rotation: true\n", ""} {
		y := realmHead + "clients:\n  web:\n" + confidential + "    redirect_uris: [https://app.example.com/cb]\n" + extra + realmKeys
		noErrors(t, validateText(t, dir, "realm", "realms/main.yaml", y, false))
	}
	// A public client may state rotation on.
	y := realmHead + "clients:\n  app:\n    refresh_token_rotation: true\n    redirect_uris: [\"com.example.app:/cb\"]\n" + realmKeys
	noErrors(t, validateText(t, dir, "realm", "realms/main.yaml", y, false))
}

// Covers: FR-32 (part), SEC-01 (part)
// Acceptance: PKCE downgrade (part)
func TestRequirePKCEWarningNamesRFC9700ForPublicClientsOnly(t *testing.T) {
	dir := keyDir(t)
	pub := realmHead + "clients:\n  app:\n    require_pkce: false\n    refresh_idle_lifetime: 24h\n    session_max_lifetime: 720h\n    redirect_uris: [\"https://app.example.com/cb\"]\n" + realmKeys
	con := realmHead + "clients:\n  app:\n" + confidential + "    require_pkce: false\n    redirect_uris: [\"https://app.example.com/cb\"]\n" + realmKeys
	if ds := validateText(t, dir, "realm", "realms/main.yaml", pub, false); len(ds) != 1 || ds[0].Severity != Warning || !strings.Contains(ds[0].Message, "RFC 9700") {
		t.Fatalf("public: %v", ds)
	}
	if ds := validateText(t, dir, "realm", "realms/main.yaml", con, false); len(ds) != 1 || ds[0].Severity != Warning || strings.Contains(ds[0].Message, "RFC 9700") {
		t.Fatalf("confidential: %v", ds)
	}
	// The default is require_pkce: true, which needs no warning.
	noErrors(t, validateText(t, dir, "realm", "realms/main.yaml", realmHead+"clients:\n  app:\n    redirect_uris: [\"https://app.example.com/cb\"]\n"+realmKeys, false))
}

// Disabled providers need none of their options and raise no warning.
//
// Covers: FR-32 (part), FR-19 (part)
// Acceptance: Config validation (part)
func TestDisabledProvidersNeedNoOptions(t *testing.T) {
	dir := keyDir(t)
	y := realmHead + "providers:\n  google: {}\n  apple: {}\n  github: {}\n  facebook: {trust_email: true}\n  oidc: {}\n" + realmKeys
	noErrors(t, validateText(t, dir, "realm", "realms/main.yaml", y, false))
	// Apple needs no client_secret_file: its secret is generated from the key.
	y = realmHead + "providers:\n  apple:\n" + appleOpts + realmKeys
	noErrors(t, validateText(t, dir, "realm", "realms/main.yaml", y, false))
}

// Covers: FR-32 (part), FR-19 (part)
// Acceptance: Config validation (part)
func TestPostgresNeedsHostAndPasswordFile(t *testing.T) {
	dir := keyDir(t)
	ds := validateText(t, dir, "database", "database.yaml", "driver: postgres\n", false)
	if len(ds) != 2 || ds[0].Field != "postgres.host" || ds[1].Field != "postgres.password_file" || ds[0].Line != 1 || ds[1].Line != 1 {
		t.Fatalf("got %v", ds)
	}
	// SQLite needs neither.
	noErrors(t, validateText(t, dir, "database", "database.yaml", "driver: sqlite\n", false))
}

// Covers: FR-32 (part)
// Acceptance: Config validation (part)
func TestClientDiagnosticsAreOrderedByClientIDAndRule(t *testing.T) {
	dir := keyDir(t)
	y := realmHead + `clients:
  b: {type: confidential, redirect_uris: ["http://127.0.0.1/cb"], web_origins: ["https://x/y"], require_pkce: false}
  a: {refresh_token_rotation: false, redirect_uris: ["https://a/cb#f"], post_logout_redirect_uris: ["https://a/b#f"]}
` + realmKeys
	first := validateText(t, dir, "realm", "realms/main.yaml", y, false)
	var fields []string
	for _, d := range first {
		fields = append(fields, d.Field)
	}
	got := strings.Join(fields, ",")
	const order = "clients.a.redirect_uris[0],clients.a.post_logout_redirect_uris[0],clients.a.refresh_token_rotation," +
		"clients.b.client_secret_file,clients.b.redirect_uris[0],clients.b.web_origins[0],clients.b.require_pkce"
	if got != order {
		t.Fatalf("got  %s\nwant %s", got, order)
	}
	for i := 0; i < 20; i++ {
		again := validateText(t, dir, "realm", "realms/main.yaml", y, false)
		if len(again) != len(first) {
			t.Fatal("count changed")
		}
		for j := range again {
			if again[j] != first[j] {
				t.Fatalf("order changed at %d: %v vs %v", j, again[j], first[j])
			}
		}
	}
}
