package oidc

import (
	"bytes"
	"context"
	"flag"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/web"
)

// deadEndpoints point at an address nothing listens on; with them every
// provider type is built without a discovery document.
const deadEndpoints = `    endpoints: {authorize: "http://127.0.0.1:9/a", token: "http://127.0.0.1:9/t", jwks: "http://127.0.0.1:9/j"}
`

// fiveProviders is the four built-in providers and a generic one, with display
// names, in key order.
const fiveProviders = `  apple:
    enabled: true
    display_name: Apple
    client_id: com.example.web
    team_id: TEAM123456
    key_id: KEY1234567
    private_key_file: secrets/main/apple.p8
    store_refresh_token: false
` + `  corp:
    type: oidc
    enabled: true
    display_name: "Corp <SSO>"
    client_id: c-id
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9"
` + deadEndpoints + `  facebook:
    enabled: true
    display_name: Facebook
    client_id: fb-id
    client_secret_file: secrets/main/facebook_secret
` + `  github:
    enabled: true
    display_name: GitHub
    client_id: gh-id
    client_secret_file: secrets/main/github_secret
` + `  google:
    enabled: true
    display_name: Google
    client_id: g-id
    client_secret_file: secrets/main/google_secret
` + deadEndpoints

var fiveSecrets = []string{"corp", "facebook", "github", "google"}

type chooserEnv struct {
	reg   *provider.Pool
	realm *config.Realm
	log   *slog.Logger
	logs  *bytes.Buffer
}

// newChooserEnv loads the realm "main" with the given providers and extra
// login_page lines (two-space indented, each ending in a newline).
func newChooserEnv(t *testing.T, providers, loginPage string) chooserEnv {
	t.Helper()
	l, d := testutil.NewProviderConfig(t, providers, fiveSecrets...)
	if loginPage != "" {
		d.Realm(t, "main", strings.Replace(testutil.ProvidersRealmYAML(providers),
			"login_page:\n  contact: help@example.com\n", "login_page:\n  contact: help@example.com\n"+loginPage, 1))
		if res := l.Reload(context.Background()); !res.Applied {
			t.Fatalf("reload: %v", res.Diagnostics)
		}
	}
	clk := clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	logs := &bytes.Buffer{}
	log := logx.New(logs, slog.LevelDebug, clk)
	r, ok := l.Current().Realm("main")
	if !ok {
		t.Fatal("realm main missing")
	}
	return chooserEnv{reg: provider.NewPool(l, clk, log), realm: r, log: log, logs: logs}
}

func (e chooserEnv) choose(hint string, original url.Values) selection {
	return chooseProvider(context.Background(), e.reg, e.log, AuthRequest{Realm: e.realm, Hint: hint}, original)
}

func keys(bs []web.Provider) []string {
	var out []string
	for _, b := range bs {
		out = append(out, string(b.Key))
	}
	return out
}

// Covers: FR-04 (part)
// Acceptance: Single provider (part)
func TestChooseProvider(t *testing.T) {
	one := `  corp:
    type: oidc
    enabled: true
    client_id: c-id
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9"
` + deadEndpoints
	twoAndHidden := one + `  github:
    enabled: true
    client_id: gh-id
    client_secret_file: secrets/main/github_secret
  stealth:
    type: oidc
    enabled: true
    hidden: true
    client_id: s-id
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9"
` + deadEndpoints + `  off:
    type: oidc
    client_id: o-id
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9"
` + deadEndpoints
	oneVisibleOneHidden := one + `  stealth:
    type: oidc
    enabled: true
    hidden: true
    client_id: s-id
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9"
` + deadEndpoints
	broken := `  corp:
    type: oidc
    enabled: true
    client_id: c-id
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9"
  github:
    enabled: true
    client_id: gh-id
    client_secret_file: secrets/main/github_secret
`
	none := `  corp:
    type: oidc
    client_id: c-id
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9"
`
	tests := []struct {
		name      string
		providers string
		hint      string
		wantKey   string   // the provider used
		wantList  []string // the chooser's buttons
		wantErr   string   // the error code
		wantLog   bool     // the unknown hint is logged
	}{
		{"one visible provider is used without a hint", one, "", "corp", nil, "", false},
		{"two visible providers show the chooser", twoAndHidden, "", "", []string{"github", "corp"}, "", false},
		{"a hint selects its provider", twoAndHidden, "github", "github", nil, "", false},
		{"a hint selects a hidden provider", twoAndHidden, "stealth", "stealth", nil, "", false},
		{"a hint beats a single visible provider", oneVisibleOneHidden, "stealth", "stealth", nil, "", false},
		{"one visible and one hidden provider use the visible one", oneVisibleOneHidden, "", "corp", nil, "", false},
		{"an unknown hint shows the chooser and is logged", twoAndHidden, "nope", "", []string{"github", "corp"}, "", true},
		{"a disabled provider's hint shows the chooser and is logged", twoAndHidden, "off", "", []string{"github", "corp"}, "", true},
		{"an unknown hint with one visible provider shows the chooser", one, "nope", "", []string{"corp"}, "", true},
		{"hints are exact", twoAndHidden, "GitHub", "", []string{"github", "corp"}, "", true},
		{"no provider at all shows an empty chooser", none, "", "", nil, "", false},
		{"a provider whose discovery fails is temporarily unavailable by hint", broken, "corp", "", nil, "temporarily_unavailable", false},
		{"a single provider whose discovery fails is temporarily unavailable", `  corp:
    type: oidc
    enabled: true
    client_id: c-id
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9"
`, "", "", nil, "temporarily_unavailable", false},
		{"a failing provider listed with a working one is still a button", broken, "", "", []string{"github", "corp"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newChooserEnv(t, tt.providers, "")
			sel := env.choose(tt.hint, url.Values{"client_id": {"web"}})
			switch {
			case tt.wantErr != "":
				if sel.err == nil || sel.err.Err.Code != tt.wantErr || sel.adapter != nil || sel.buttons != nil {
					t.Fatalf("selection %+v, want error %s", sel, tt.wantErr)
				}
			case tt.wantKey != "":
				if sel.err != nil || sel.adapter == nil || string(sel.key) != tt.wantKey || sel.buttons != nil {
					t.Fatalf("selection %+v, want provider %s", sel, tt.wantKey)
				}
			default:
				if sel.err != nil || sel.adapter != nil || !slices.Equal(keys(sel.buttons), tt.wantList) {
					t.Fatalf("selection %+v (buttons %v), want the chooser %v", sel, keys(sel.buttons), tt.wantList)
				}
			}
			logged := strings.Contains(env.logs.String(), "unknown or disabled provider")
			if logged && !strings.Contains(env.logs.String(), `"provider":"`+tt.hint+`"`) {
				t.Errorf("the log does not name the hint %q:\n%s", tt.hint, env.logs)
			}
			if tt.wantLog != logged {
				t.Errorf("hint logged = %v, want %v\n%s", logged, tt.wantLog, env.logs)
			}
		})
	}
}

// Covers: FR-04 (part)
func TestChooserOrder(t *testing.T) {
	env := newChooserEnv(t, fiveProviders, "  provider_order: [github, apple]\n")
	sel := env.choose("", url.Values{})
	if got, want := keys(sel.buttons), []string{"github", "apple", "corp", "facebook", "google"}; !slices.Equal(got, want) {
		t.Errorf("buttons %v, want %v", got, want)
	}
	for _, b := range sel.buttons {
		wantBrand := string(b.Key)
		if b.Key == "corp" {
			wantBrand = "oidc"
		}
		if b.Brand != wantBrand {
			t.Errorf("%s: brand %q, want %q", b.Key, b.Brand, wantBrand)
		}
		if b.Name != env.realm.Providers[b.Key].DisplayName {
			t.Errorf("%s: name %q", b.Key, b.Name)
		}
	}
}

// Covers: FR-04 (part)
// Acceptance: Chooser links (part)
func TestChooserLinksKeepEveryParameter(t *testing.T) {
	env := newChooserEnv(t, fiveProviders, "")
	original := url.Values{
		"client_id": {"web"}, "redirect_uri": {"https://app.example.com/callback"}, "response_type": {"code"},
		"scope": {"openid profile"}, "state": {"a&b=c d"}, "nonce": {"n/1+2"}, "code_challenge": {"c"},
		"code_challenge_method": {"S256"}, "response_mode": {"fragment"}, "prompt": {"login"}, "max_age": {"60"},
		"login_hint": {"ann@example.com"}, "ui_locales": {"nl"}, "x-extra": {"é ü"},
		"provider": {"unknown"}, // the hint that brought the user here is replaced
		"idp":      {"other"},   // a different hint name is kept
	}
	sel := env.choose("unknown", original)
	if len(sel.buttons) != 5 {
		t.Fatalf("%d buttons", len(sel.buttons))
	}
	for _, b := range sel.buttons {
		u, err := url.Parse(b.Href)
		if err != nil {
			t.Fatal(err)
		}
		if u.Path != "/main/authorize" || u.Host != "" || u.Scheme != "" {
			t.Errorf("%s: link %q", b.Key, b.Href)
		}
		want := cloneValues(original)
		want.Set("provider", string(b.Key))
		if got := u.Query(); got.Encode() != want.Encode() {
			t.Errorf("%s: parameters\n got %v\nwant %v", b.Key, got, want)
		}
	}
	if original.Get("provider") != "unknown" {
		t.Error("the original values were changed")
	}
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = slices.Clone(vs)
	}
	return out
}

// Covers: FR-33 (part)
// Acceptance: Provider buttons (part)
func TestChooserGolden(t *testing.T) {
	env := newChooserEnv(t, fiveProviders, "  accent_color: \"#c2185b\"\n  logo_url: https://example.com/logo.png\n")
	sel := env.choose("", url.Values{"client_id": {"web"}, "state": {"a&b"}})
	rec := httptest.NewRecorder()
	web.NewPages().Page(rec, httptest.NewRequest("GET", "/main/authorize", nil), env.realm, web.Page{Kind: web.PageChooser, Providers: sel.buttons})
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	path := filepath.Join("testdata", "chooser.golden.html")
	// The -update flag is defined by the external tests of this package.
	if f := flag.Lookup("update"); f != nil && f.Value.String() == "true" {
		if err := os.WriteFile(path, rec.Body.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Body.String() != string(want) {
		t.Errorf("chooser differs from %s (run go test ./internal/oidc -update and review the diff):\n%s", path, rec.Body)
	}
	// The built-in providers draw their own buttons; the generic one takes the accent.
	body := rec.Body.String()
	for _, class := range []string{"brand-google", "brand-apple", "brand-github", "brand-facebook", "brand-generic"} {
		if strings.Count(body, `class="button `+class+`"`) != 1 {
			t.Errorf("want one %s button", class)
		}
	}
}

var cssRule = regexp.MustCompile(`([^{}]+)\{([^}]*)\}`)

// Covers: FR-33 (part)
// Acceptance: Provider buttons (part)
func TestStylesheetButtonsAreEqualAndAccentIsGeneric(t *testing.T) {
	env := newChooserEnv(t, fiveProviders, "  accent_color: \"#c2185b\"\n")
	rec := httptest.NewRecorder()
	web.Assets(rec, httptest.NewRequest("GET", "/main/assets/style.css", nil), env.realm)
	css := rec.Body.String()
	var buttonSize, accentSelectors []string
	for _, m := range cssRule.FindAllStringSubmatch(css, -1) {
		sel, body := strings.TrimSpace(m[1]), m[2]
		if strings.Contains(body, "var(--accent)") {
			accentSelectors = append(accentSelectors, sel)
		}
		if sel == "a.button" {
			buttonSize = append(buttonSize, body)
		}
		// A brand rule may style the button, but never resize it.
		if strings.HasPrefix(sel, "a.brand-") && !strings.Contains(sel, " ") {
			for _, prop := range []string{"width", "height", "min-height", "padding", "margin", "font-size"} {
				if regexp.MustCompile(`(^|[;\s])`+prop+`\s*:`).MatchString(body) && sel != "a.brand-google" {
					t.Errorf("%s sets %s: buttons must keep one size", sel, prop)
				}
			}
		}
	}
	if len(buttonSize) != 1 || !strings.Contains(buttonSize[0], "height: 48px") || !strings.Contains(buttonSize[0], "width: 100%") {
		t.Errorf("the button size is not set once for every button: %q", buttonSize)
	}
	if want := []string{"a", "a.brand-generic"}; !slices.Equal(accentSelectors, want) {
		t.Errorf("the accent colour is used by %v, want %v (the page's links and the generic button only)", accentSelectors, want)
	}
}

// Covers: FR-55
// Acceptance: Login page branding
func TestLoginPageBranding(t *testing.T) {
	l, d := testutil.NewProviderConfig(t, fiveProviders, fiveSecrets...)
	realmYAML := strings.Replace(testutil.ProvidersRealmYAML(fiveProviders), "name: main\n", "name: main\ndisplay_name: Example Realm\n", 1)
	realmYAML = strings.Replace(realmYAML, "login_page:\n  contact: help@example.com\n",
		"login_page:\n  contact: help@example.com\n  logo_url: https://example.com/logo.png\n  accent_color: \"#c2185b\"\n  provider_order: [github, apple]\n", 1)
	d.Realm(t, "main", realmYAML)
	if res := l.Reload(context.Background()); !res.Applied {
		t.Fatalf("reload: %v", res.Diagnostics)
	}
	realm, ok := l.Current().Realm("main")
	if !ok {
		t.Fatal("realm main missing")
	}
	clk := clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	log := logx.New(&bytes.Buffer{}, slog.LevelDebug, clk)
	sel := chooseProvider(context.Background(), provider.NewPool(l, clk, log), log, AuthRequest{Realm: realm}, url.Values{})
	render := func(p web.Page) string {
		rec := httptest.NewRecorder()
		web.NewPages().Page(rec, httptest.NewRequest("GET", "/main/authorize", nil), realm, p)
		return rec.Body.String()
	}

	// The chooser: display name, logo, and the two named providers first in
	// the order named, then the others.
	if got, want := keys(sel.buttons), []string{"github", "apple", "corp", "facebook", "google"}; !slices.Equal(got, want) {
		t.Errorf("buttons %v, want %v", got, want)
	}
	body := render(web.Page{Kind: web.PageChooser, Providers: sel.buttons})
	if !strings.Contains(body, "Example Realm") {
		t.Errorf("the chooser lacks the display name:\n%s", body)
	}
	if !strings.Contains(body, `class="logo" src="https://example.com/logo.png"`) {
		t.Errorf("the chooser lacks the logo:\n%s", body)
	}
	// The contact is on the error page and the data-deletion page.
	for name, p := range map[string]web.Page{
		"error":         {Kind: web.PageError, Status: 400, MessageID: "error.invalid_request"},
		"data deletion": {Kind: web.PageDataDeletion},
	} {
		if b := render(p); !strings.Contains(b, `mailto:help@example.com`) {
			t.Errorf("the %s page lacks the contact:\n%s", name, b)
		}
	}
	// The accent is on links and the generic button only; the built-in buttons
	// keep their vendor colours and logos.
	rec := httptest.NewRecorder()
	web.Assets(rec, httptest.NewRequest("GET", "/main/assets/style.css", nil), realm)
	css := rec.Body.String()
	if !strings.Contains(css, "--accent: #c2185b;") {
		t.Errorf("the stylesheet lacks the accent colour:\n%s", css)
	}
	var accentSelectors []string
	for _, m := range cssRule.FindAllStringSubmatch(css, -1) {
		if strings.Contains(m[2], "var(--accent)") {
			accentSelectors = append(accentSelectors, strings.TrimSpace(m[1]))
		}
	}
	if want := []string{"a", "a.brand-generic"}; !slices.Equal(accentSelectors, want) {
		t.Errorf("the accent colour is used by %v, want %v", accentSelectors, want)
	}
	for _, class := range []string{"brand-google", "brand-apple", "brand-github", "brand-facebook"} {
		if !strings.Contains(body, `class="button `+class+`"`) {
			t.Errorf("the chooser lacks the built-in %s button", class)
		}
	}
	for _, logo := range []string{"logos/google.png", "logos/apple.svg", "logos/github.svg", "logos/facebook.png"} {
		if !strings.Contains(body, logo) {
			t.Errorf("the chooser lacks the bundled %s", logo)
		}
	}
}

func TestTruncateUTF8(t *testing.T) {
	for _, tt := range []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 5, "abc"},
		{"abcdef", 3, "abc"},
		{"aé", 2, "a"}, // é is two bytes: cut before it
		{"aé", 3, "aé"},
		{"日本語", 4, "日"},
		{"日本語", 2, ""},
	} {
		if got := truncateUTF8(tt.in, tt.n); got != tt.want || !utf8.ValidString(got) {
			t.Errorf("truncateUTF8(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
		}
	}
}
