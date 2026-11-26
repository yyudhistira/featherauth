package web_test

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/web"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const realmExtra = `display_name: Example Realm
login_page:
  logo_url: https://example.com/logo.png
  accent_color: "#ff6600"
  contact: help@example.com
` + testutil.DefaultClients

func newRealm(t *testing.T, extra string) *config.Realm {
	t.Helper()
	return newRealmIn(t, serverDefaultYAML, extra)
}

const serverDefaultYAML = "public_url: https://auth.example.com\n"

func newRealmIn(t *testing.T, server, extra string) *config.Realm {
	t.Helper()
	src := testutil.NewConfig(t, server, map[string]string{"main": testutil.RealmYAML("main", extra)})
	r, ok := src.Current().Realm("main")
	if !ok {
		t.Fatal("no realm")
	}
	return r
}

func render(t *testing.T, realm *config.Realm, acceptLanguage string, p web.Page) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/main/authorize", nil)
	if acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}
	rec := httptest.NewRecorder()
	web.NewPages().Page(rec, req, realm, p)
	return rec
}

var chooser = web.Page{Kind: web.PageChooser, Providers: []web.Provider{
	{Key: "google", Name: "Google", Brand: "google", Href: "/main/authorize?client_id=web&state=a%26b&provider=google"},
	{Key: "apple", Name: "Apple", Brand: "apple", Href: "/main/authorize?client_id=web&provider=apple"},
	{Key: "github", Name: "GitHub", Brand: "github", Href: "/main/authorize?client_id=web&provider=github"},
	{Key: "facebook", Name: "Facebook", Brand: "facebook", Href: "/main/authorize?client_id=web&provider=facebook"},
	{Key: "corp", Name: "Corp <SSO>", Href: "/main/authorize?client_id=web&provider=corp"},
}}

var pages = []struct {
	name string
	page web.Page
	code int
}{
	{"chooser", chooser, 200},
	{"chooser_empty", web.Page{Kind: web.PageChooser}, 200},
	{"error", web.Page{Kind: web.PageError, Status: 400, MessageID: "error.invalid_request"}, 400},
	{"error_expired", web.Page{Kind: web.PageError, Status: 400, MessageID: "error.request_expired"}, 400},
	{"error_unknown_id", web.Page{Kind: web.PageError, Status: 500, MessageID: "error.no_such_id"}, 500},
	{"signed_out", web.Page{Kind: web.PageSignedOut}, 200},
	{"data_deletion", web.Page{Kind: web.PageDataDeletion}, 200},
	{"data_deletion_code", web.Page{Kind: web.PageDataDeletion, Code: "aB3dE5gH7jK9mN1pQ3rS5t"}, 200},
	{"form_post", web.Page{Kind: web.PageFormPost, Action: "https://app.example.com/callback?x=1", Fields: []web.Field{
		{Name: "code", Value: "abc\"<>"}, {Name: "state", Value: "s 1"}, {Name: "iss", Value: "https://auth.example.com/main"},
	}}, 200},
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/web -update)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs from the page; run go test ./internal/web -update and review the diff.\n--- got ---\n%s", path, got)
	}
}

func TestPagesMatchTheirGoldenFiles(t *testing.T) {
	realm := newRealm(t, realmExtra)
	for _, p := range pages {
		t.Run(p.name, func(t *testing.T) {
			rec := render(t, realm, "", p.page)
			if rec.Code != p.code {
				t.Errorf("status %d, want %d", rec.Code, p.code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
				t.Errorf("content type %q", ct)
			}
			golden(t, p.name+".golden.html", rec.Body.Bytes())
		})
	}
}

func TestPagesWithoutContactOrLogo(t *testing.T) {
	realm := newRealm(t, testutil.DefaultClients)
	for _, name := range []string{"data_deletion", "error"} {
		for _, p := range pages {
			if p.name != name {
				continue
			}
			body := render(t, realm, "", p.page).Body.String()
			if strings.Contains(body, "mailto:") || strings.Contains(body, "help@example.com") {
				t.Errorf("%s shows a contact the realm does not have", name)
			}
		}
	}
	if body := render(t, realm, "", chooser).Body.String(); strings.Contains(body, `class="logo"`) {
		t.Error("the chooser shows a logo the realm does not have")
	}
}

func TestContactAsURL(t *testing.T) {
	realm := newRealm(t, "login_page:\n  contact: https://example.com/help\n"+testutil.DefaultClients)
	body := render(t, realm, "", web.Page{Kind: web.PageDataDeletion}).Body.String()
	if !strings.Contains(body, `href="https://example.com/help"`) {
		t.Errorf("no link to the contact URL in %s", body)
	}
}

// Covers: SEC-12 (part)
// Acceptance: Browser headers (part)
func TestEveryPageCarriesTheBrowserHeaders(t *testing.T) {
	realm := newRealm(t, realmExtra)
	for _, p := range pages {
		t.Run(p.name, func(t *testing.T) {
			h := render(t, realm, "", p.page).Header()
			want := map[string]string{
				"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
				"X-Content-Type-Options":    "nosniff",
				"X-Robots-Tag":              "noindex",
				"Referrer-Policy":           "no-referrer",
				"Cache-Control":             "no-store",
			}
			for k, v := range want {
				if got := h.Get(k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
			csp := h.Get("Content-Security-Policy")
			if !strings.Contains(csp, "frame-ancestors 'none'") {
				t.Errorf("CSP %q has no frame-ancestors 'none'", csp)
			}
			if p.page.Kind != web.PageFormPost && csp != realm.SecurityHeaders.ContentSecurityPolicy {
				t.Errorf("CSP %q is not the realm's %q", csp, realm.SecurityHeaders.ContentSecurityPolicy)
			}
		})
	}
}

// Covers: SEC-12 (part)
// Acceptance: Browser headers (part)
func TestSecurityHeadersFollowTheRealm(t *testing.T) {
	realm := newRealm(t, "security_headers:\n  hsts: \"\"\n  content_security_policy: \"default-src 'none'; frame-ancestors 'none'\"\n"+testutil.DefaultClients)
	h := http.Header{}
	web.SecurityHeaders(realm, h)
	if v, ok := h["Strict-Transport-Security"]; ok {
		t.Errorf("an empty hsts is sent: %q", v)
	}
	if got := h.Get("Content-Security-Policy"); got != "default-src 'none'; frame-ancestors 'none'" {
		t.Errorf("CSP %q", got)
	}
	for _, k := range []string{"X-Content-Type-Options", "X-Robots-Tag", "Referrer-Policy", "Cache-Control"} {
		if h.Get(k) == "" {
			t.Errorf("%s missing", k)
		}
	}

	realm = newRealm(t, "security_headers:\n  content_security_policy: \"\"\n"+testutil.DefaultClients)
	h = http.Header{}
	web.SecurityHeaders(realm, h)
	if v, ok := h["Content-Security-Policy"]; ok {
		t.Errorf("an empty CSP is sent: %q", v)
	}
	if h.Get("Strict-Transport-Security") == "" {
		t.Error("the default hsts is missing")
	}
}

func TestPageSetsHeadersBeforeTheStatus(t *testing.T) {
	// Headers set after WriteHeader are lost; a recorder keeps the snapshot.
	realm := newRealm(t, realmExtra)
	rec := render(t, realm, "", web.Page{Kind: web.PageError, Status: 503, MessageID: "error.server"})
	if rec.Code != 503 || rec.Result().Header.Get("Cache-Control") != "no-store" {
		t.Errorf("status %d, headers %v", rec.Code, rec.Result().Header)
	}
}

func TestUnknownPageKindIsAServerError(t *testing.T) {
	realm := newRealm(t, realmExtra)
	rec := render(t, realm, "", web.Page{Kind: 0})
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status %d", rec.Code)
	}
}

func TestFormPostWithAnUnsafeActionIsAServerError(t *testing.T) {
	realm := newRealm(t, realmExtra)
	for _, a := range []string{"javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "", "://bad", "/relative"} {
		rec := render(t, realm, "", web.Page{Kind: web.PageFormPost, Action: a})
		if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "<form") {
			t.Errorf("action %q: status %d", a, rec.Code)
		}
	}
}

// Covers: FR-33 (part)
func TestStylesheetCarriesTheAccentColour(t *testing.T) {
	for _, layout := range []struct{ name, server, assets string }{
		{"default", serverDefaultYAML, "/main/assets"},
		{"keycloak prefix", "public_url: https://auth.example.com\nurls:\n  path_prefix: /auth\n  endpoints:\n    assets: \"{prefix}/static/{realm}\"\n", "/auth/static/main"},
	} {
		t.Run(layout.name, func(t *testing.T) {
			realm := newRealmIn(t, layout.server, realmExtra)
			if got := realm.EndpointPath(config.EndpointAssets, ""); got != layout.assets {
				t.Fatalf("assets path %q, want %q", got, layout.assets)
			}
			req := httptest.NewRequest("GET", layout.assets+"/style.css", nil)
			rec := httptest.NewRecorder()
			web.Assets(rec, req, realm)
			if rec.Code != 200 {
				t.Fatalf("status %d", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
				t.Errorf("content type %q", ct)
			}
			css := rec.Body.String()
			if !strings.Contains(css, "--accent: #ff6600;") {
				t.Errorf("the accent colour is not a custom property:\n%.200s", css)
			}
			if !strings.Contains(css, "var(--accent)") {
				t.Error("the stylesheet does not use the accent colour")
			}
			// The pages link the stylesheet at the same path.
			body := render(t, realm, "", chooser).Body.String()
			if !strings.Contains(body, `href="`+layout.assets+`/style.css"`) {
				t.Errorf("the chooser does not link %s/style.css", layout.assets)
			}
		})
	}
}

func TestAccentColourIsPerRealm(t *testing.T) {
	a := newRealm(t, "login_page:\n  accent_color: \"#111111\"\n"+testutil.DefaultClients)
	b := newRealm(t, "login_page:\n  accent_color: \"#222222\"\n"+testutil.DefaultClients)
	for realm, want := range map[*config.Realm]string{a: "#111111", b: "#222222"} {
		rec := httptest.NewRecorder()
		web.Assets(rec, httptest.NewRequest("GET", "/main/assets/style.css", nil), realm)
		if !strings.Contains(rec.Body.String(), "--accent: "+want+";") {
			t.Errorf("want accent %s", want)
		}
	}
}

// Covers: FR-33 (part)
func TestProviderLogosAreServed(t *testing.T) {
	realm := newRealm(t, realmExtra)
	for _, c := range []struct{ file, typ, magic string }{
		{"google.png", "image/png", "\x89PNG"},
		{"apple.svg", "image/svg+xml", "<svg"},
		{"github.svg", "image/svg+xml", "<svg"},
		{"facebook.png", "image/png", "\x89PNG"},
	} {
		rec := httptest.NewRecorder()
		web.Assets(rec, httptest.NewRequest("GET", "/main/assets/logos/"+c.file, nil), realm)
		if rec.Code != 200 || rec.Header().Get("Content-Type") != c.typ || !strings.Contains(rec.Body.String(), c.magic) {
			t.Errorf("%s: status %d, type %q", c.file, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	for _, gone := range []string{"google.svg", "facebook.svg"} {
		rec := httptest.NewRecorder()
		web.Assets(rec, httptest.NewRequest("GET", "/main/assets/logos/"+gone, nil), realm)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s is gone: status %d", gone, rec.Code)
		}
	}
}

func TestUnknownAssetsAre404(t *testing.T) {
	realm := newRealm(t, realmExtra)
	for _, p := range []string{
		"/main/assets/", "/main/assets/nope.css", "/main/assets/logos/nope.svg", "/main/assets/../style.css",
		"/main/assets/logos/../../templates/layout.html", "/main/assets/%2e%2e/style.css", "/other/path",
	} {
		rec := httptest.NewRecorder()
		web.Assets(rec, httptest.NewRequest("GET", p, nil), realm)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d", p, rec.Code)
		}
	}
}

func TestNegotiate(t *testing.T) {
	supported := []string{"en", "nl", "de"}
	tests := []struct {
		header, def, want string
	}{
		{"", "en", "en"},
		{"nl", "en", "nl"},
		{"NL", "en", "nl"},
		{"nl-BE", "en", "nl"},
		{"fr, nl;q=0.5, de;q=0.9", "en", "de"},
		{"fr", "en", "en"},
		{"fr", "de", "de"},
		{"*", "de", "de"},
		{"nl;q=0, de;q=0.1", "en", "de"},
		{"nl;q=0", "en", "en"},
		{"nl;q=abc, de", "en", "nl"},
		{"nl-BE;q=0.2, de;q=0.8", "en", "de"},
		{";;;, ,nl", "en", "nl"},
		{"x-klingon, en-GB", "de", "en"},
		{"nlx", "en", "en"},
	}
	for _, tt := range tests {
		if got := web.Negotiate(tt.header, supported, tt.def); got != tt.want {
			t.Errorf("Negotiate(%q, default %s) = %q, want %q", tt.header, tt.def, got, tt.want)
		}
	}
}

// Covers: FR-15 (part), FR-57 (part)
// Acceptance: Locale
func TestDutchAppearsAfterAddingATranslationWithoutARestart(t *testing.T) {
	src, dir := testutil.NewConfigDir(t, serverDefaultYAML, map[string]string{"main": testutil.MinimalRealm("main")})
	chooserBody := func() string {
		realm, _ := src.Current().Realm("main")
		rec := render(t, realm, "nl", chooser)
		return rec.Body.String()
	}
	body := chooserBody()
	if !strings.Contains(body, "Choose how you want to sign in.") || !strings.Contains(body, `lang="en"`) {
		t.Fatalf("only en is supported, so the page is English:\n%s", body)
	}

	dir.Write(t, "locales/nl.yaml", "chooser.title: Inloggen\nchooser.prompt: Kies hoe u wilt inloggen.\nchooser.sign_in_with: Inloggen met {name}\n")
	testutil.WriteRealm(t, dir, "main", testutil.RealmYAML("main", "login_page:\n  supported_locales: [en, nl]\n"+testutil.DefaultClients))
	if res := src.Reload(t.Context()); !res.Applied {
		t.Fatalf("reload: %+v", res)
	}
	body = chooserBody()
	for _, want := range []string{`lang="nl"`, "<h1>Inloggen</h1>", "Kies hoe u wilt inloggen.", "Inloggen met Google"} {
		if !strings.Contains(body, want) {
			t.Errorf("the Dutch page lacks %q:\n%s", want, body)
		}
	}
	realm, _ := src.Current().Realm("main")
	if body := render(t, realm, "fr", chooser).Body.String(); !strings.Contains(body, `lang="en"`) {
		t.Error("an unsupported language does not fall back to the default locale")
	}
}

// Covers: FR-15 (part), FR-57 (part)
// Acceptance: Locale
func TestAnIDMissingFromATranslationShowsInEnglish(t *testing.T) {
	src, dir := testutil.NewConfigDir(t, serverDefaultYAML, map[string]string{"main": testutil.MinimalRealm("main")})
	dir.Write(t, "locales/nl.yaml", "chooser.title: Inloggen\n")
	testutil.WriteRealm(t, dir, "main", testutil.RealmYAML("main", "login_page:\n  supported_locales: [en, nl]\n"+testutil.DefaultClients))
	if res := src.Reload(t.Context()); !res.Applied {
		t.Fatalf("reload: %+v", res)
	}
	realm, _ := src.Current().Realm("main")
	body := render(t, realm, "nl", chooser).Body.String()
	if !strings.Contains(body, "<h1>Inloggen</h1>") {
		t.Error("the translated id is not used")
	}
	if !strings.Contains(body, "Choose how you want to sign in.") || !strings.Contains(body, "Sign in with Google") {
		t.Errorf("ids missing from nl.yaml are not shown in English:\n%s", body)
	}
	if !strings.Contains(body, "<span>Log in with Facebook</span>") {
		t.Errorf("the Facebook button on the nl page does not fall back to Log in with Facebook:\n%s", body)
	}
}

// Covers: FR-57
// Acceptance: Page language
func TestPageLanguage(t *testing.T) {
	src, dir := testutil.NewConfigDir(t, serverDefaultYAML, map[string]string{"main": testutil.MinimalRealm("main")})
	realmWith := func(t *testing.T, loginPage string) *config.Realm {
		t.Helper()
		testutil.WriteRealm(t, dir, "main", testutil.RealmYAML("main", "login_page:\n"+loginPage+testutil.DefaultClients))
		if res := src.Reload(t.Context()); !res.Applied {
			t.Fatalf("reload: %+v", res)
		}
		r, _ := src.Current().Realm("main")
		return r
	}
	both := realmWith(t, "  supported_locales: [en, id]\n")
	idPage := render(t, both, "id", chooser).Body.String()
	english := render(t, both, "en", chooser).Body.String()
	if !strings.Contains(idPage, `lang="id"`) || !strings.Contains(english, `lang="en"`) || idPage == english ||
		strings.Contains(idPage, "Choose how you want to sign in.") {
		t.Fatalf("the Indonesian and English choosers are not told apart:\n%s\n%s", idPage, english)
	}

	for _, c := range []struct {
		name, loginPage, accept, wantLang string
	}{
		{"preferred language among the supported", "  supported_locales: [en, id]\n", "id, en;q=0.5", "id"},
		{"no supported language falls back to English", "  supported_locales: [en, id]\n", "fr", "en"},
		{"no supported language falls back to the realm default", "  supported_locales: [en, id]\n  default_locale: id\n", "fr", "id"},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := render(t, realmWith(t, c.loginPage), c.accept, chooser).Body.String()
			if !strings.Contains(body, `lang="`+c.wantLang+`"`) {
				t.Fatalf("want lang %q:\n%s", c.wantLang, body)
			}
			if want := map[string]string{"en": english, "id": idPage}[c.wantLang]; body != want {
				t.Errorf("the %s page differs from the %s chooser:\n%s", c.wantLang, c.wantLang, body)
			}
		})
	}

	// A translation file that lacks one message id: that message shows in
	// English and the others are translated.
	dir.Write(t, "locales/nl.yaml", "chooser.title: Inloggen\nchooser.sign_in_with: Inloggen met {name}\n")
	body := render(t, realmWith(t, "  supported_locales: [en, nl]\n"), "nl", chooser).Body.String()
	for _, want := range []string{`lang="nl"`, "<h1>Inloggen</h1>", "Inloggen met Google", "Choose how you want to sign in."} {
		if !strings.Contains(body, want) {
			t.Errorf("the page with a lacking message id lacks %q:\n%s", want, body)
		}
	}
}

func TestErrorPageWithAnUnknownIDFallsBackToTheServerMessage(t *testing.T) {
	realm := newRealm(t, realmExtra)
	body := render(t, realm, "", web.Page{Kind: web.PageError, Status: 500, MessageID: "error.no_such_id"}).Body.String()
	if !strings.Contains(body, web.English["error.server"]) || strings.Contains(body, "no_such_id") {
		t.Errorf("body %s", body)
	}
}

// Covers: FR-04 (part)
// Acceptance: Provider buttons (part)
func TestFacebookButtonSaysLogInWith(t *testing.T) {
	realm := newRealm(t, realmExtra)
	body := render(t, realm, "", chooser).Body.String()
	for _, want := range []string{"<span>Sign in with Google</span>", "<span>Sign in with Apple</span>", "<span>Sign in with GitHub</span>", "<span>Log in with Facebook</span>", "<span>Sign in with Corp &lt;SSO&gt;</span>"} {
		if !strings.Contains(body, want) {
			t.Errorf("the chooser lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Sign in with Facebook") {
		t.Error("the Facebook button still says Sign in with")
	}
}

// Covers: FR-40
// Acceptance: Meta deletion callback (part)
func TestDataDeletionCodeIsEscaped(t *testing.T) {
	realm := newRealm(t, realmExtra)
	body := render(t, realm, "", web.Page{Kind: web.PageDataDeletion, Code: `<script>alert("x")</script>&`}).Body.String()
	if strings.Contains(body, "<script>alert") || !strings.Contains(body, "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;&amp;") {
		t.Errorf("the code is not escaped by html/template: %s", body)
	}
	plain := render(t, realm, "", web.Page{Kind: web.PageDataDeletion}).Body.String()
	if strings.Contains(plain, "confirmation code") {
		t.Errorf("a page without a code shows the sentence: %s", plain)
	}
}
