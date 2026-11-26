package oidc_test

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// deliverHandlers is a server.Handlers whose callback endpoint delivers the
// given result, so that Deliver runs under the router with a realm in its
// request context, as in the service.
type deliverHandlers struct {
	mode oidc.ResponseMode
	uri  string
	p    url.Values
}

var _ server.Handlers = (*deliverHandlers)(nil)

func (d *deliverHandlers) Callback(w http.ResponseWriter, r *http.Request) {
	oidc.Deliver(w, r, d.mode, d.uri, d.p)
}
func (d *deliverHandlers) Discovery(http.ResponseWriter, *http.Request)        {}
func (d *deliverHandlers) Authorize(http.ResponseWriter, *http.Request)        {}
func (d *deliverHandlers) CallbackContinue(http.ResponseWriter, *http.Request) {}
func (d *deliverHandlers) Token(http.ResponseWriter, *http.Request)            {}
func (d *deliverHandlers) Userinfo(http.ResponseWriter, *http.Request)         {}
func (d *deliverHandlers) JWKS(http.ResponseWriter, *http.Request)             {}
func (d *deliverHandlers) Logout(http.ResponseWriter, *http.Request)           {}
func (d *deliverHandlers) Revoke(http.ResponseWriter, *http.Request)           {}
func (d *deliverHandlers) Sessions(http.ResponseWriter, *http.Request)         {}
func (d *deliverHandlers) AccountDelete(http.ResponseWriter, *http.Request)    {}
func (d *deliverHandlers) Assets(http.ResponseWriter, *http.Request)           {}
func (d *deliverHandlers) ProviderEvents(http.ResponseWriter, *http.Request)   {}
func (d *deliverHandlers) DataDeletion(http.ResponseWriter, *http.Request)     {}

func deliver(t *testing.T, mode oidc.ResponseMode, uri string, p url.Values) *httptest.ResponseRecorder {
	t.Helper()
	src := testutil.NewConfig(t, "public_url: https://auth.example.com\n", map[string]string{"main": testutil.MinimalRealm("main")})
	clk := clock.NewFake(testStart)
	rt := server.NewHandler(src, &deliverHandlers{mode: mode, uri: uri, p: p},
		server.Middleware{Logger: logx.New(&strings.Builder{}, 0, clk), Clock: clk})
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest("GET", "/main/callback/google", nil))
	return rec
}

func success(extra ...string) url.Values {
	v := url.Values{"code": {"abc123"}, "iss": {"https://auth.example.com/main"}, "state": {"st ate/1"}}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func TestDeliverQueryAndFragment(t *testing.T) {
	tests := []struct {
		name string
		mode oidc.ResponseMode
		uri  string
		p    url.Values
		want string
	}{
		{"query", oidc.ModeQuery, "https://app.example.com/cb", success(),
			"https://app.example.com/cb?code=abc123&iss=https%3A%2F%2Fauth.example.com%2Fmain&state=st+ate%2F1"},
		{"query keeps the existing query", oidc.ModeQuery, "https://app.example.com/cb?tenant=a%20b&x=1", success(),
			"https://app.example.com/cb?tenant=a%20b&x=1&code=abc123&iss=https%3A%2F%2Fauth.example.com%2Fmain&state=st+ate%2F1"},
		{"query, custom scheme", oidc.ModeQuery, "com.example.app:/callback", success(),
			"com.example.app:/callback?code=abc123&iss=https%3A%2F%2Fauth.example.com%2Fmain&state=st+ate%2F1"},
		{"query, loopback", oidc.ModeQuery, "http://127.0.0.1:8123/callback", success(),
			"http://127.0.0.1:8123/callback?code=abc123&iss=https%3A%2F%2Fauth.example.com%2Fmain&state=st+ate%2F1"},
		{"query, error", oidc.ModeQuery, "https://app.example.com/cb",
			url.Values{"error": {"access_denied"}, "error_description": {"the user cancelled"}, "iss": {"https://auth.example.com/main"}, "state": {"s"}},
			"https://app.example.com/cb?error=access_denied&error_description=the+user+cancelled&iss=https%3A%2F%2Fauth.example.com%2Fmain&state=s"},
		{"query without state", oidc.ModeQuery, "https://app.example.com/cb",
			url.Values{"code": {"c"}, "iss": {"https://auth.example.com/main"}},
			"https://app.example.com/cb?code=c&iss=https%3A%2F%2Fauth.example.com%2Fmain"},
		{"query after an empty query", oidc.ModeQuery, "https://app.example.com/cb?", url.Values{"iss": {"i"}},
			"https://app.example.com/cb?iss=i"},
		{"query after a trailing ampersand", oidc.ModeQuery, "https://app.example.com/cb?a=1&", url.Values{"iss": {"i"}},
			"https://app.example.com/cb?a=1&iss=i"},
		{"fragment", oidc.ModeFragment, "https://app.example.com/cb", success(),
			"https://app.example.com/cb#code=abc123&iss=https%3A%2F%2Fauth.example.com%2Fmain&state=st+ate%2F1"},
		{"fragment keeps the existing query", oidc.ModeFragment, "https://app.example.com/cb?tenant=a", success(),
			"https://app.example.com/cb?tenant=a#code=abc123&iss=https%3A%2F%2Fauth.example.com%2Fmain&state=st+ate%2F1"},
		{"fragment, error without state", oidc.ModeFragment, "https://app.example.com/cb",
			url.Values{"error": {"server_error"}, "iss": {"https://auth.example.com/main"}},
			"https://app.example.com/cb#error=server_error&iss=https%3A%2F%2Fauth.example.com%2Fmain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := deliver(t, tt.mode, tt.uri, tt.p)
			if rec.Code != http.StatusFound {
				t.Fatalf("status %d", rec.Code)
			}
			if got := rec.Header().Get("Location"); got != tt.want {
				t.Errorf("Location\n got %s\nwant %s", got, tt.want)
			}
		})
	}
}

// Covers: FR-06 (part), SEC-19 (part)
// Acceptance: Response modes (part)
func TestDeliverPutsEveryValueInTheRightPlace(t *testing.T) {
	const uri = "https://app.example.com/cb?tenant=a"
	t.Run("query", func(t *testing.T) {
		u, _ := url.Parse(deliver(t, oidc.ModeQuery, uri, success()).Header().Get("Location"))
		q := u.Query()
		if u.Fragment != "" || q.Get("tenant") != "a" || q.Get("code") != "abc123" || q.Get("state") != "st ate/1" || q.Get("iss") != "https://auth.example.com/main" {
			t.Errorf("got %v #%s", q, u.Fragment)
		}
	})
	t.Run("fragment", func(t *testing.T) {
		u, _ := url.Parse(deliver(t, oidc.ModeFragment, uri, success()).Header().Get("Location"))
		f, err := url.ParseQuery(u.Fragment)
		if err != nil {
			t.Fatal(err)
		}
		if u.Query().Get("code") != "" || u.Query().Get("tenant") != "a" || f.Get("code") != "abc123" || f.Get("state") != "st ate/1" || f.Get("iss") != "https://auth.example.com/main" {
			t.Errorf("query %v fragment %v", u.Query(), f)
		}
	})
}

// Covers: SEC-19 (part)
func TestDeliverRefusesAResultWithoutIss(t *testing.T) {
	// Every authorization response, success or error, carries iss (RFC 9207).
	for _, mode := range []oidc.ResponseMode{oidc.ModeQuery, oidc.ModeFragment, oidc.ModeFormPost} {
		for _, p := range []url.Values{
			{"code": {"c"}, "state": {"s"}},
			{"error": {"access_denied"}, "iss": {""}},
		} {
			rec := deliver(t, mode, "https://app.example.com/cb", p)
			if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" || strings.Contains(rec.Body.String(), "<form") {
				t.Errorf("%s %v: status %d, Location %q", mode, p, rec.Code, rec.Header().Get("Location"))
			}
		}
	}
}

func TestDeliverRefusesAnUnknownMode(t *testing.T) {
	rec := deliver(t, oidc.ResponseMode("web_message"), "https://app.example.com/cb", success())
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" {
		t.Errorf("status %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDeliverWithoutARealmInTheContext(t *testing.T) {
	rec := httptest.NewRecorder()
	oidc.Deliver(rec, httptest.NewRequest("GET", "/", nil), oidc.ModeQuery, "https://app.example.com/cb", success())
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" {
		t.Errorf("status %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestParseResponseMode(t *testing.T) {
	for in, want := range map[string]oidc.ResponseMode{"query": oidc.ModeQuery, "fragment": oidc.ModeFragment, "form_post": oidc.ModeFormPost} {
		got, ok := oidc.ParseResponseMode(in)
		if !ok || got != want {
			t.Errorf("%s: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "QUERY", "web_message", "query.jwt"} {
		if _, ok := oidc.ParseResponseMode(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

var scriptRE = regexp.MustCompile(`<script>(.*)</script>`)

// Covers: FR-06 (part), FR-33 (part), SEC-19 (part)
// Acceptance: Response modes (part)
// Acceptance: form_post in browsers (part)
func TestDeliverFormPost(t *testing.T) {
	rec := deliver(t, oidc.ModeFormPost, "https://app.example.com/cb?tenant=a", success())
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	golden(t, "form_post.golden.html", rec.Body.Bytes())

	// The CSP lists exactly the script's hash and the target origin.
	m := scriptRE.FindStringSubmatch(body)
	if m == nil || strings.Count(body, "<script") != 1 {
		t.Fatalf("want exactly one script in %s", body)
	}
	sum := sha256.Sum256([]byte(m[1]))
	hash := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	directives := map[string][]string{}
	for _, d := range strings.Split(rec.Header().Get("Content-Security-Policy"), ";") {
		f := strings.Fields(d)
		if len(f) > 0 {
			directives[f[0]] = f[1:]
		}
	}
	want := map[string][]string{
		"default-src":     {"'none'"},
		"script-src":      {hash},
		"form-action":     {"https://app.example.com"},
		"frame-ancestors": {"'none'"},
	}
	if len(directives) != len(want) {
		t.Errorf("CSP directives %v", directives)
	}
	for k, v := range want {
		if strings.Join(directives[k], " ") != strings.Join(v, " ") {
			t.Errorf("CSP %s = %v, want %v", k, directives[k], v)
		}
	}
	// A submit button for browsers without scripts.
	if !strings.Contains(body, `<button type="submit">`) {
		t.Error("no submit button")
	}
	// The values go in as hidden fields, the query of the target stays in the action.
	for _, want := range []string{`action="https://app.example.com/cb?tenant=a"`, `name="code" value="abc123"`, `name="state" value="st ate/1"`, `name="iss" value="https://auth.example.com/main"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the form lacks %s", want)
		}
	}
	// The security headers of browser pages.
	for k, v := range map[string]string{"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex"} {
		if rec.Header().Get(k) != v {
			t.Errorf("%s = %q", k, rec.Header().Get(k))
		}
	}
}

func TestDeliverFormPostCSPForOtherTargets(t *testing.T) {
	tests := []struct{ uri, source string }{
		{"com.example.app:/callback", "com.example.app:"},
		{"http://127.0.0.1:8123/callback", "http://127.0.0.1:8123"},
		{"https://app.example.com:8443/cb", "https://app.example.com:8443"},
	}
	for _, tt := range tests {
		rec := deliver(t, oidc.ModeFormPost, tt.uri, success())
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action "+tt.source+";") {
			t.Errorf("%s: CSP %q", tt.uri, csp)
		}
	}
}

func TestDeliverFormPostError(t *testing.T) {
	rec := deliver(t, oidc.ModeFormPost, "https://app.example.com/cb",
		url.Values{"error": {"access_denied"}, "error_description": {"cancelled"}, "iss": {"https://auth.example.com/main"}})
	for _, want := range []string{`name="error" value="access_denied"`, `name="error_description" value="cancelled"`, `name="iss"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(rec.Body.String(), `name="state"`) {
		t.Error("a state nobody sent")
	}
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
		t.Fatalf("%v (run go test ./internal/oidc -update)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs from the page; run go test ./internal/oidc -update and review the diff.\n--- got ---\n%s", path, got)
	}
}
