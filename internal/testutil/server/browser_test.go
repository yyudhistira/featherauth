//go:build browser

package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// The browser tests are not scanned by govulncheck (it follows the default
// build tags), so chromedp and its modules are checked only by their use
// here, never shipped: no non-test file imports them.
//
// The browser tests drive a real Chrome against the in-process service. The
// service answers over TLS on loopback; Chrome maps the public hosts of the
// service and of the client applications to it, so the cookies, the redirects
// and the cross-site POSTs behave as in production.

// seen is a request the test site received and the answer it gave.
type seen struct {
	Host, Method, Path, Query string
	HasCookie                 bool
	CookieNames               []string
	Status                    int
	Header                    http.Header
	SetCookies                []*http.Cookie
	Form                      url.Values
	Body                      string
}

// arrival is a callback request that waits for release; state is the state
// the service sent to the provider.
type arrival struct {
	state   string
	release chan struct{}
}

// site serves the realm on auth.example.com and a recording page on every
// other host (the client applications).
type site struct {
	env *server.Env

	mu       sync.Mutex
	seen     []seen
	changed  chan struct{}
	holding  bool
	arrivals chan *arrival
	// app, when set, answers the requests to appHost.
	app     http.Handler
	appHost string
}

type statusWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := seen{Host: r.Host, Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, HasCookie: r.Header.Get("Cookie") != ""}
	for _, c := range r.Cookies() {
		rec.CookieNames = append(rec.CookieNames, c.Name)
	}
	if app, host := s.appHandler(); app != nil && r.Host == host {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		app.ServeHTTP(sw, r)
		rec.Status = sw.status
		s.add(rec)
		return
	}
	if r.Host != "auth.example.com" {
		_ = r.ParseForm()
		rec.Form = r.PostForm
		rec.Status = http.StatusOK
		s.add(rec)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!DOCTYPE html><title>client</title><p>client application"))
		return
	}
	if s.isHolding() && r.URL.Query().Get("state") != "probe" && strings.HasPrefix(r.URL.Path, "/main/callback/") {
		a := &arrival{state: r.URL.Query().Get("state"), release: make(chan struct{})}
		s.arrivals <- a
		<-a.release
	}
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	s.env.Router.ServeHTTP(sw, r)
	rec.Status = sw.status
	rec.Body = sw.body.String()
	rec.Header = w.Header().Clone()
	rec.SetCookies = (&http.Response{Header: rec.Header}).Cookies()
	s.add(rec)
}

// serveApp makes the site answer the requests to host with h, instead of the
// recording page.
func (s *site) serveApp(host string, h http.Handler) {
	s.mu.Lock()
	s.app, s.appHost = h, host
	s.mu.Unlock()
}

func (s *site) appHandler() (http.Handler, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.app, s.appHost
}

func (s *site) add(r seen) {
	s.mu.Lock()
	s.seen = append(s.seen, r)
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
}

func (s *site) isHolding() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.holding
}

// hold makes every callback of the realm wait until its arrival is released.
func (s *site) hold() {
	s.mu.Lock()
	s.holding = true
	s.mu.Unlock()
}

// find returns the requests that match.
func (s *site) find(match func(seen) bool) []seen {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []seen
	for _, r := range s.seen {
		if match(r) {
			out = append(out, r)
		}
	}
	return out
}

// await waits until a request matches and returns the first one.
func (s *site) await(t *testing.T, ctx context.Context, match func(seen) bool) seen {
	t.Helper()
	for {
		s.mu.Lock()
		changed := s.changed
		s.mu.Unlock()
		if got := s.find(match); len(got) > 0 {
			return got[0]
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for a request: %v", ctx.Err())
		}
	}
}

func toClient(app server.App, method string) func(seen) bool {
	u, _ := url.Parse(app.RedirectURI)
	return func(r seen) bool { return r.Host == u.Host && r.Path == u.Path && r.Method == method }
}

// start returns the service, the test site and a Chrome context that reaches it.
func start(t *testing.T, flags []string, opts ...server.Option) (*site, context.Context) {
	t.Helper()
	s := &site{env: server.New(t, opts...), changed: make(chan struct{}), arrivals: make(chan *arrival, 2)}
	for key, m := range s.env.Mocks {
		m.SetUser(mockidp.User{Sub: "sub-" + key, Name: "Ann Example", Email: "ann@example.com", EmailVerified: true})
	}
	srv := httptest.NewUnstartedServer(s)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	var rules []string
	for _, h := range []string{"auth.example.com", "app.example.com", "post.example.com"} {
		rules = append(rules, "MAP "+h+" "+addr)
	}
	// Test-only flags: Chrome runs as the CI user in a container-like
	// sandbox (NoSandbox) and trusts the httptest certificate, which no CA
	// signed; nothing here reaches production code.
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoSandbox,
		// A cold Chrome on a shared CI runner can take longer than the
		// default 20 seconds to print its debugging address.
		chromedp.WSURLReadTimeout(60*time.Second),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("host-resolver-rules", strings.Join(rules, ",")),
	)
	for _, f := range flags {
		name, value, _ := strings.Cut(strings.TrimPrefix(f, "--"), "=")
		allocOpts = append(allocOpts, chromedp.Flag(name, value))
	}
	alloc, cancelAlloc := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	t.Cleanup(cancelAlloc)
	ctx, cancel := chromedp.NewContext(alloc)
	t.Cleanup(cancel)
	ctx, cancelTimeout := context.WithTimeout(ctx, 90*time.Second)
	t.Cleanup(cancelTimeout)
	if err := chromedp.Run(ctx); err != nil {
		t.Fatalf("start Chrome: %v", err)
	}
	return s, ctx
}

func authorizeURL(env *server.Env, v url.Values) string {
	return env.Realm.EndpointURL(config.EndpointAuthorize, "") + "?" + v.Encode()
}

// Covers: FR-33, SEC-12
// Acceptance: form_post in browsers
func TestBrowserFormPostSubmitsItself(t *testing.T) {
	s, ctx := start(t, nil)
	app := server.ClientFormPost
	if err := chromedp.Run(ctx, chromedp.Navigate(authorizeURL(s.env, server.Authorize(app, "google")))); err != nil {
		t.Fatal(err)
	}
	post := s.await(t, ctx, toClient(app, http.MethodPost))
	if post.Form.Get("code") == "" || post.Form.Get("state") != "st-1" {
		t.Fatalf("the client got %v, want a code and state st-1", post.Form)
	}
	cbPath := s.env.Realm.EndpointPath(config.EndpointCallback, "google")
	pages := s.find(func(r seen) bool {
		return r.Host == "auth.example.com" && r.Path == cbPath && r.Method == http.MethodGet
	})
	if len(pages) != 1 {
		t.Fatalf("%d callback pages, want 1", len(pages))
	}
	csp := pages[0].Header.Get("Content-Security-Policy")
	var scriptSrc, formAction string
	for _, d := range strings.Split(csp, ";") {
		name, value, _ := strings.Cut(strings.TrimSpace(d), " ")
		switch name {
		case "script-src":
			scriptSrc = value
		case "form-action":
			formAction = value
		}
	}
	if strings.Contains(csp, "unsafe-") || formAction != "https://post.example.com" {
		t.Fatalf("CSP %q must allow only the script's hash and the target origin", csp)
	}
	hashes := regexp.MustCompile(`^'sha256-([A-Za-z0-9+/=]+)'$`).FindStringSubmatch(scriptSrc)
	scripts := regexp.MustCompile(`(?s)<script>(.*?)</script>`).FindAllStringSubmatch(pages[0].Body, -1)
	if hashes == nil || len(scripts) != 1 {
		t.Fatalf("script-src %q with %d inline scripts, want exactly one hash and one script", scriptSrc, len(scripts))
	}
	sum := sha256.Sum256([]byte(scripts[0][1]))
	if base64.StdEncoding.EncodeToString(sum[:]) != hashes[1] {
		t.Fatalf("the page's script %q does not match the hash in %q", scripts[0][1], scriptSrc)
	}
}

// Covers: FR-33, SEC-12
// Acceptance: form_post in browsers
func TestBrowserFormPostWithoutScriptsUsesTheButton(t *testing.T) {
	s, ctx := start(t, []string{"--blink-settings=scriptEnabled=false"})
	app := server.ClientFormPost
	err := chromedp.Run(ctx,
		chromedp.Navigate(authorizeURL(s.env, server.Authorize(app, "google"))),
		chromedp.WaitVisible(`form button[type=submit]`, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatal(err)
	}
	// With scripting disabled the parser keeps the noscript content as
	// elements; with scripting enabled it would be text.
	var disabled bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.querySelector('noscript > button') !== null`, &disabled)); err != nil {
		t.Fatal(err)
	}
	if !disabled {
		t.Fatal("scripts are enabled in this Chrome: the test proves nothing")
	}
	if got := s.find(toClient(app, http.MethodPost)); len(got) != 0 {
		t.Fatalf("the form submitted itself with scripts disabled: %v", got)
	}
	if err := chromedp.Run(ctx, chromedp.Click(`form button[type=submit]`, chromedp.ByQuery)); err != nil {
		t.Fatal(err)
	}
	post := s.await(t, ctx, toClient(app, http.MethodPost))
	if post.Form.Get("code") == "" || post.Form.Get("state") != "st-1" {
		t.Fatalf("the client got %v, want a code and state st-1", post.Form)
	}
}

// stateCookies returns the names of the state cookies Chrome sends to the
// callback path now: it loads a callback URL the service ignores and reads
// the cookie header the site recorded.
func stateCookies(t *testing.T, ctx context.Context, s *site) []string {
	t.Helper()
	before := len(s.find(isProbe))
	if err := chromedp.Run(ctx, chromedp.Navigate(s.env.Realm.EndpointURL(config.EndpointCallback, "google")+"?state=probe")); err != nil {
		t.Fatal(err)
	}
	got := s.find(isProbe)
	if len(got) != before+1 {
		t.Fatalf("%d probe requests, want %d", len(got), before+1)
	}
	var out []string
	for _, n := range got[before].CookieNames {
		if strings.HasPrefix(n, "fa_state_") {
			out = append(out, n)
		}
	}
	return out
}

func isProbe(r seen) bool {
	return r.Host == "auth.example.com" && strings.Contains(r.Query, "state=probe")
}

// Covers: FR-05, SEC-08
// Acceptance: State cookie
func TestBrowserTwoTabsFinishInReverseOrder(t *testing.T) {
	s, ctx := start(t, nil)
	app := server.ClientQuery
	tabA, cancelA := chromedp.NewContext(ctx)
	defer cancelA()
	tabB, cancelB := chromedp.NewContext(ctx)
	defer cancelB()
	for _, tab := range []context.Context{tabA, tabB} {
		if err := chromedp.Run(tab); err != nil {
			t.Fatal(err)
		}
	}
	s.hold()
	done := make(chan error, 2)
	login := func(tab context.Context, state string) *arrival {
		go func() {
			done <- chromedp.Run(tab, chromedp.Navigate(authorizeURL(s.env, server.Authorize(app, "google", "state", state))))
		}()
		select {
		case a := <-s.arrivals:
			return a
		case err := <-done:
			t.Fatalf("a tab ended before its callback: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		return nil
	}
	a, b := login(tabA, "st-A"), login(tabB, "st-B")

	cookies := stateCookies(t, ctx, s)
	if len(cookies) != 2 {
		t.Fatalf("%d state cookies while both logins wait, want 2", len(cookies))
	}
	wantPath := s.env.Realm.StateCookiePath()
	timeout := s.env.Realm.Tokens.LoginTimeout.Std()
	for _, state := range []string{a.state, b.state} {
		name := oidc.StateCookieName(state)
		var set []*http.Cookie
		for _, r := range s.find(func(r seen) bool { return r.Path == "/main/authorize" }) {
			for _, c := range r.SetCookies {
				if c.Name == name {
					set = append(set, c)
				}
			}
		}
		if len(set) != 1 || set[0].Path != wantPath || set[0].MaxAge != int(timeout.Seconds()) {
			t.Fatalf("cookie %s set as %+v, want Path %s and Max-Age %d", name, set, wantPath, int(timeout.Seconds()))
		}
		if !slices.Contains(cookies, name) {
			t.Fatalf("Chrome sent no cookie %s, only %v", name, cookies)
		}
	}

	close(b.release)
	s.await(t, ctx, func(r seen) bool { return toClient(app, http.MethodGet)(r) && strings.Contains(r.Query, "state=st-B") })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := stateCookies(t, ctx, s); len(got) != 1 || got[0] != oidc.StateCookieName(a.state) {
		t.Fatalf("after tab B finished, cookies are %v, want only the one of tab A", got)
	}
	close(a.release)
	s.await(t, ctx, func(r seen) bool { return toClient(app, http.MethodGet)(r) && strings.Contains(r.Query, "state=st-A") })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := stateCookies(t, ctx, s); len(got) != 0 {
		t.Fatalf("state cookies %v remain after both logins", got)
	}
}

// Covers: FR-05, SEC-03, SEC-08
// Acceptance: Apple callback
func TestBrowserAppleCallbackCrossSitePost(t *testing.T) {
	s, ctx := start(t, nil)
	app := server.ClientQuery
	if err := chromedp.Run(ctx, chromedp.Navigate(authorizeURL(s.env, server.Authorize(app, "apple")))); err != nil {
		t.Fatal(err)
	}
	final := s.await(t, ctx, toClient(app, http.MethodGet))
	if !strings.Contains(final.Query, "code=") || !strings.Contains(final.Query, "state=st-1") {
		t.Fatalf("the client got %q, want a code and state st-1", final.Query)
	}
	callback := func(method string) func(seen) bool {
		return func(r seen) bool {
			return r.Host == "auth.example.com" && r.Method == method && r.Path == s.env.Realm.EndpointPath(config.EndpointCallback, "apple")
		}
	}
	post := s.find(callback(http.MethodPost))
	if len(post) != 1 || post[0].HasCookie || post[0].Status != http.StatusSeeOther {
		t.Fatalf("the cross-site POST was %+v, want one without a cookie answered 303", post)
	}
	next, err := url.Parse(post[0].Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cont := s.find(func(r seen) bool {
		return r.Method == http.MethodGet && r.Path == next.Path && r.Host == "auth.example.com"
	})
	if len(cont) != 1 || !cont[0].HasCookie {
		t.Fatalf("the continue request was %+v, want one carrying the Lax cookie", cont)
	}
	for _, r := range s.find(func(seen) bool { return true }) {
		for _, c := range r.SetCookies {
			if c.SameSite == http.SameSiteNoneMode {
				t.Fatalf("cookie %s is SameSite=None", c.Name)
			}
		}
	}
}

// Covers: FR-04, FR-33, FR-55 (part)
// Acceptance: Provider buttons
func TestBrowserProviderButtonsOnAPhone(t *testing.T) {
	const accent = "rgb(170, 51, 0)" // accent_color #aa3300
	s, ctx := start(t, nil, server.WithLoginSetting(`accent_color: "#aa3300"`))
	type button struct {
		Class, Background, Src   string
		Left, Top, Width, Height float64
		ImgHeight                float64
		Text, Overflow           string
		Loaded                   bool
	}
	var buttons []button
	var innerHeight, scrollHeight float64
	var linkColour string
	err := chromedp.Run(ctx,
		chromedp.EmulateViewport(360, 640),
		chromedp.Navigate(authorizeURL(s.env, server.Authorize(server.ClientQuery, ""))),
		chromedp.WaitVisible(`a.button`, chromedp.ByQuery),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('a.button')).map(a => {
			const r = a.getBoundingClientRect(), i = a.querySelector('img');
			return {Class: a.className, Background: getComputedStyle(a).backgroundColor,
				Src: i ? i.getAttribute('src') : '', Loaded: i ? i.complete && i.naturalWidth > 0 : false, ImgHeight: i ? i.getBoundingClientRect().height : 0, Text: a.innerText.trim(), Overflow: getComputedStyle(a).overflow,
				Left: r.left, Top: r.top, Width: r.width, Height: r.height};
		})`, &buttons),
		chromedp.Evaluate(`window.innerHeight`, &innerHeight),
		chromedp.Evaluate(`document.documentElement.scrollHeight`, &scrollHeight),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(buttons) != 5 {
		t.Fatalf("%d buttons, want 5: %+v", len(buttons), buttons)
	}
	if scrollHeight > innerHeight {
		t.Errorf("the page is %v high in a %v high window: buttons need scrolling", scrollHeight, innerHeight)
	}
	colours := map[string]string{
		"google": "rgb(255, 255, 255)", "apple": "rgb(0, 0, 0)", "github": "rgb(36, 41, 47)", "facebook": "rgb(24, 119, 242)",
	}
	texts := map[string]string{
		"google": "Sign in with Google", "apple": "Sign in with Apple", "github": "Sign in with GitHub", "facebook": "Log in with Facebook",
	}
	assets := s.env.Realm.EndpointPath(config.EndpointAssets, "")
	var genericBackground string
	logoHeights := map[string]float64{}
	var overflow string
	for _, b := range buttons {
		if b.Top < 0 || b.Top+b.Height > innerHeight || b.Left < 0 || b.Left+b.Width > 360 {
			t.Errorf("button %q at %+v is not fully visible", b.Class, b)
		}
		if b.Width != buttons[0].Width || b.Height != buttons[0].Height {
			t.Errorf("button %q is %vx%v, the first is %vx%v", b.Class, b.Width, b.Height, buttons[0].Width, buttons[0].Height)
		}
		_, key, found := strings.Cut(b.Class, "brand-")
		if !found {
			t.Fatalf("button %q has no brand class", b.Class)
		}
		if want, ok := texts[key]; ok && b.Text != want {
			t.Errorf("%s button says %q, want %q (the default display_name is the vendor's name)", key, b.Text, want)
		}
		logoHeights[key] = b.ImgHeight
		if key == "apple" {
			overflow = b.Overflow
		}
		if want, ok := colours[key]; ok {
			if b.Background != want {
				t.Errorf("%s button is %s, want %s", key, b.Background, want)
			}
			if !strings.HasPrefix(b.Src, assets+"/logos/") || !b.Loaded {
				t.Errorf("%s logo %q (loaded %v) must come from %s", key, b.Src, b.Loaded, assets)
			}
		} else {
			genericBackground = b.Background
			if b.Src != "" {
				t.Errorf("the generic button has a logo %q", b.Src)
			}
		}
	}
	// apple.svg draws its mark 19 units high in a square of 56 units, so the
	// mark is as tall as the image times 19/56. It must be at least as tall as
	// the 20 px marks of the GitHub and Facebook buttons, and the black square
	// of the image, which is larger than the button, must be clipped by it.
	const appleMarkUnits, appleImageUnits, minMark = 19.0, 56.0, 20.0
	if mark := logoHeights["apple"] * appleMarkUnits / appleImageUnits; mark < minMark {
		t.Errorf("the Apple mark is %.1fpx high (image %vpx), want at least %vpx like the GitHub and Facebook marks", mark, logoHeights["apple"], minMark)
	}
	if overflow != "hidden" {
		t.Errorf("the Apple button has overflow %q: its logo's black square would show outside the button", overflow)
	}
	for key, c := range colours {
		if c == accent {
			t.Errorf("the accent colour shows on the %s button", key)
		}
	}
	// The same buttons at desktop width.
	var sizes [][2]float64
	err = chromedp.Run(ctx,
		chromedp.EmulateViewport(1280, 800),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('a.button')).map(a => {
			const r = a.getBoundingClientRect(); return [r.width, r.height]; })`, &sizes),
	)
	if err != nil {
		t.Fatal(err)
	}
	// Links carry the accent too; the contact link is on the error page.
	err = chromedp.Run(ctx,
		chromedp.Navigate(authorizeURL(s.env, server.Authorize(server.App{ID: "nobody", RedirectURI: "https://x.example.com/cb"}, ""))),
		chromedp.Evaluate(`getComputedStyle(document.querySelector('main a')).color`, &linkColour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if genericBackground != accent || linkColour != accent {
		t.Errorf("generic button %s and link %s, want accent %s on both", genericBackground, linkColour, accent)
	}
	if len(sizes) != 5 {
		t.Fatalf("%d buttons at desktop width, want 5", len(sizes))
	}
	for _, sz := range sizes {
		if sz != sizes[0] {
			t.Errorf("at desktop width a button is %v, the first is %v", sz, sizes[0])
		}
	}
	chooser := s.find(func(r seen) bool { return r.Path == "/main/authorize" })
	if len(chooser) == 0 {
		t.Fatal("no chooser request")
	}
	if got, want := chooser[0].Header.Get("Content-Security-Policy"), s.env.Realm.SecurityHeaders.ContentSecurityPolicy; got != want {
		t.Errorf("chooser CSP %q, want the realm's %q", got, want)
	}
	for _, r := range s.find(func(r seen) bool { return strings.HasPrefix(r.Path, assets) }) {
		if r.Status != http.StatusOK {
			t.Errorf("asset %s answered %d", r.Path, r.Status)
		}
	}
}

// Covers: SEC-12, FR-33
// Acceptance: Browser headers
func TestBrowserEveryPageCarriesTheHeaders(t *testing.T) {
	s, ctx := start(t, nil)
	env := s.env
	pages := []struct {
		name string
		url  string
		path string
		code int
	}{
		{"chooser", authorizeURL(env, server.Authorize(server.ClientQuery, "")), "/main/authorize", 200},
		{"error page", authorizeURL(env, server.Authorize(server.App{ID: "nobody", RedirectURI: "https://x.example.com/cb"}, "")), "/main/authorize", 400},
		{"signed out", env.Realm.EndpointURL(config.EndpointLogout, ""), env.Realm.EndpointPath(config.EndpointLogout, ""), 200},
		{"data deletion", env.Realm.EndpointURL(config.EndpointDataDeletion, ""), env.Realm.EndpointPath(config.EndpointDataDeletion, ""), 200},
	}
	for _, p := range pages {
		if err := chromedp.Run(ctx, chromedp.Navigate(p.url)); err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		got := s.find(func(r seen) bool { return r.Host == "auth.example.com" && r.Path == p.path && r.Header != nil })
		if len(got) == 0 {
			t.Fatalf("%s: no request for %s", p.name, p.path)
		}
		checkHeaders(t, p.name, got[len(got)-1], p.code)
	}
	app := server.ClientQuery
	if err := chromedp.Run(ctx, chromedp.Navigate(authorizeURL(env, server.Authorize(app, "google")))); err != nil {
		t.Fatal(err)
	}
	s.await(t, ctx, toClient(app, http.MethodGet))
	cbPath := env.Realm.EndpointPath(config.EndpointCallback, "google")
	cb := s.find(func(r seen) bool {
		return r.Host == "auth.example.com" && r.Path == cbPath && r.Method == http.MethodGet && !isProbe(r)
	})
	if len(cb) != 1 {
		t.Fatalf("%d callback requests, want 1", len(cb))
	}
	checkHeaders(t, "callback redirect", cb[0], http.StatusFound)
}

func checkHeaders(t *testing.T, name string, r seen, status int) {
	t.Helper()
	if r.Status != status {
		t.Errorf("%s: status %d, want %d", name, r.Status, status)
	}
	want := map[string]string{
		"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
	}
	for k, v := range want {
		if got := r.Header.Get(k); got != v {
			t.Errorf("%s: %s = %q, want %q", name, k, got, v)
		}
	}
	if got := r.Header.Get("X-Robots-Tag"); got != "noindex" {
		t.Errorf("%s: X-Robots-Tag = %q, want noindex", name, got)
	}
	if got := r.Header.Get("Strict-Transport-Security"); !strings.Contains(got, "max-age=") {
		t.Errorf("%s: Strict-Transport-Security = %q, want a max-age", name, got)
	}
	if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("%s: CSP %q lacks frame-ancestors 'none'", name, csp)
	}
}
