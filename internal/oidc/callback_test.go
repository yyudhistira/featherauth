package oidc_test

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	tsrv "github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/token"
	"github.com/yyudhistira/featherauth/internal/user"
)

// A login of the tests: what the browser holds after the provider has answered.
type login struct {
	state  string       // the state sent to the provider
	cookie *http.Cookie // the state cookie of the login
	target string       // path and query the provider sent the browser to
	mode   oidc.ResponseMode
	idp    *mockidp.Server
}

// modeClients are one client of each response mode of authzClients.
var modeClients = []struct {
	name   string
	mode   oidc.ResponseMode
	client string
	uri    string
}{
	{"query", oidc.ModeQuery, "web", "https://app.example.com/callback"},
	{"fragment", oidc.ModeFragment, "frag", "https://frag.example.com/callback"},
	{"form_post", oidc.ModeFormPost, "posting", "https://post.example.com/callback"},
}

// begin starts a login at the provider through /authorize and lets the mock
// provider answer it, so the result is what the browser would carry to the
// callback.
func (e *authzEnv) begin(t *testing.T, prov string, v url.Values) login {
	t.Helper()
	rec := e.get(v)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize: status %d, body %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("authorize set %d cookies", len(cookies))
	}
	idp := e.gh
	if prov != "github" {
		idp = e.idp
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rec.Header().Get("Location"), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	back := mustURL(t, resp.Header.Get("Location"))
	mode, _ := oidc.ParseResponseMode(v.Get("response_mode"))
	if mode == "" {
		mode = oidc.ModeQuery
	}
	return login{state: back.Query().Get("state"), cookie: cookies[0], target: back.RequestURI(), mode: mode, idp: idp}
}

// beginMode starts a login of the client that has the response mode.
func (e *authzEnv) beginMode(t *testing.T, prov string, m int, extra ...string) login {
	t.Helper()
	c := modeClients[m]
	l := e.begin(t, prov, goodRequest(append([]string{"provider", prov, "client_id", c.client, "redirect_uri", c.uri}, extra...)...))
	l.mode = c.mode
	return l
}

// callback answers the browser's request to target with the cookies.
func (e *authzEnv) callback(target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", target, nil)
	req.RemoteAddr = "192.0.2.10:4000"
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.rt.ServeHTTP(rec, req)
	return rec
}

// wantErrorResult checks an error delivered to the client: the code, the
// echoed state (none when want is empty), the realm's iss, a description, and
// no code.
func wantErrorResult(t *testing.T, rec *httptest.ResponseRecorder, mode oidc.ResponseMode, code, state string) {
	t.Helper()
	got := result(t, rec, mode)
	if got.Get("error") != code {
		t.Errorf("error = %q, want %q (%v)", got.Get("error"), code, got)
	}
	if got.Get("state") != state {
		t.Errorf("state = %q, want %q", got.Get("state"), state)
	}
	if got.Get("iss") != issuer {
		t.Errorf("iss = %q, want %q", got.Get("iss"), issuer)
	}
	if got.Get("error_description") == "" {
		t.Error("no error_description")
	}
	if got.Has("code") {
		t.Errorf("an error result carries a code: %v", got)
	}
}

// wantCookieDeleted checks that the answer deletes the state cookie of the
// login: its name, the callback path and an end of life now.
func wantCookieDeleted(t *testing.T, rec *httptest.ResponseRecorder, l login) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == l.cookie.Name {
			if c.MaxAge >= 0 || c.Path != "/main/callback/" || c.Value != "" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
				t.Errorf("cookie not deleted properly: %+v", c)
			}
			return
		}
	}
	t.Errorf("the state cookie %s is not deleted: %v", l.cookie.Name, rec.Header().Values("Set-Cookie"))
}

// wantNoExchange checks that no provider was asked to exchange a code.
func (e *authzEnv) wantNoExchange(t *testing.T) {
	t.Helper()
	if n := e.gh.TokenCalls(); n != 0 {
		t.Errorf("%d code exchanges at github", n)
	}
	if n := e.idp.TokenCalls(); n != 0 {
		t.Errorf("%d code exchanges at the generic provider", n)
	}
}

// asProvider points a callback target at another provider's path.
func asProvider(target, prov string) string {
	return strings.Replace(target, "/callback/corp", "/callback/"+prov, 1)
}

// Covers: FR-05 (part), SEC-19 (part)
// Acceptance: Mix-up
func TestCallbackRefusesAnotherProvidersPath(t *testing.T) {
	for i, m := range modeClients {
		t.Run(m.name, func(t *testing.T) {
			e := newAuthzEnv(t, "github", "corp")
			l := e.beginMode(t, "corp", i)
			if !strings.HasPrefix(l.target, "/main/callback/corp?") {
				t.Fatalf("callback target %s", l.target)
			}
			rec := e.callback(asProvider(l.target, "github"), l.cookie)
			wantErrorResult(t, rec, m.mode, "access_denied", "st-1")
			wantCookieDeleted(t, rec, l)
			e.wantNoExchange(t)
		})
	}
}

// wantPageRefusal checks the HTML page of an unknown or expired request: no
// redirect, no result for the client.
func wantPageRefusal(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("redirected to %s", loc)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type %q, want HTML", ct)
	}
	if !strings.Contains(rec.Body.String(), "unknown or has expired") {
		t.Errorf("not the expired-request page: %s", rec.Body)
	}
}

// Covers: FR-05 (part), SEC-08 (part)
// Acceptance: State cookie (part)
func TestCallbackChecksTheStateCookie(t *testing.T) {
	cases := []struct {
		name   string
		cookie func(l login, other login) []*http.Cookie
	}{
		{"missing", func(l, o login) []*http.Cookie { return nil }},
		{"another value", func(l, o login) []*http.Cookie {
			c := *l.cookie
			c.Value = "not-the-state"
			return []*http.Cookie{&c}
		}},
		{"only another login's cookie", func(l, o login) []*http.Cookie { return []*http.Cookie{o.cookie} }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := newAuthzEnv(t, "github", "corp")
			l := e.begin(t, "corp", goodRequest("provider", "corp"))
			other := e.begin(t, "corp", goodRequest("provider", "corp"))
			rec := e.callback(l.target, tt.cookie(l, other)...)
			wantErrorResult(t, rec, oidc.ModeQuery, "access_denied", "st-1")
			wantCookieDeleted(t, rec, l)
			e.wantNoExchange(t)
		})
	}
}

// Covers: FR-05 (part)
// Acceptance: Provider error or cancel
func TestCallbackProviderErrors(t *testing.T) {
	cases := []struct {
		name     string
		provider string // the error the mock sends
		want     string
	}{
		{"cancel", "access_denied", "access_denied"},
		{"provider error", "server_error", "server_error"},
		{"temporarily_unavailable from the provider is a server_error", "temporarily_unavailable", "server_error"},
	}
	for _, tt := range cases {
		for i, m := range modeClients {
			t.Run(tt.name+" "+m.name, func(t *testing.T) {
				e := newAuthzEnv(t, "github", "corp")
				e.gh.SetAuthorizeError(tt.provider)
				l := e.beginMode(t, "github", i)
				rec := e.callback(l.target, l.cookie)
				wantErrorResult(t, rec, m.mode, tt.want, "st-1")
				wantCookieDeleted(t, rec, l)
				e.wantNoExchange(t)
			})
		}
	}
	t.Run("a request without state gets none", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		e.gh.SetAuthorizeError("access_denied")
		l := e.begin(t, "github", goodRequest("provider", "github", "state", "-"))
		rec := e.callback(l.target, l.cookie)
		wantErrorResult(t, rec, oidc.ModeQuery, "access_denied", "")
	})
	t.Run("the provider's own description is not passed on", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		e.gh.SetAuthorizeError("access_denied")
		l := e.begin(t, "github", goodRequest("provider", "github"))
		rec := e.callback(l.target+"&error_description=secret+words", l.cookie)
		if got := result(t, rec, oidc.ModeQuery); strings.Contains(got.Encode(), "secret") {
			t.Errorf("the provider's description reached the client: %v", got)
		}
	})
}

// Covers: FR-05 (part)
// Acceptance: Provider error or cancel
func TestCallbackShowsAPageForAnUnknownOrExpiredRequest(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		l := e.begin(t, "github", goodRequest("provider", "github"))
		e.clk.Advance(10 * time.Minute) // login_timeout
		rec := e.callback(l.target, l.cookie)
		wantPageRefusal(t, rec)
		wantCookieDeleted(t, rec, l)
		e.wantNoExchange(t)
	})
	t.Run("unknown state", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		l := e.begin(t, "github", goodRequest("provider", "github"))
		target := "/main/callback/github?code=c&state=unknown"
		rec := e.callback(target, l.cookie)
		wantPageRefusal(t, rec)
		e.wantNoExchange(t)
	})
	t.Run("no state", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		wantPageRefusal(t, e.callback("/main/callback/github?code=c"))
		wantPageRefusal(t, e.callback("/main/callback/github?code=c&state=a&state=b"))
	})
	t.Run("another realm's request", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		l := e.begin(t, "github", goodRequest("provider", "github"))
		wantPageRefusal(t, e.callback(strings.Replace(l.target, "/main/", "/closed/", 1), l.cookie))
		e.wantNoExchange(t)
	})
	t.Run("a client the realm no longer has", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		l := e.begin(t, "github", goodRequest("provider", "github"))
		e.rewrite(t, l.state, func(r *store.AuthRequest) { r.ClientID = "gone" })
		wantPageRefusal(t, e.callback(l.target, l.cookie))
		e.wantNoExchange(t)
	})
}

// rewrite changes the stored login of the state.
func (e *authzEnv) rewrite(t *testing.T, state string, f func(*store.AuthRequest)) {
	t.Helper()
	err := e.st.Write(context.Background(), func(tx store.Tx) error {
		r, err := tx.AuthRequests().Get(context.Background(), store.AuthRequestID(state))
		if err != nil {
			return err
		}
		if err := tx.AuthRequests().Delete(context.Background(), r.ID); err != nil {
			return err
		}
		f(&r)
		return tx.AuthRequests().Create(context.Background(), r)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Covers: FR-05 (part)
func TestCallbackProviderThatCannotBeBuiltIsUnavailable(t *testing.T) {
	e := newAuthzEnv(t, "github", "broken")
	l := e.begin(t, "github", goodRequest("provider", "github"))
	e.rewrite(t, l.state, func(r *store.AuthRequest) { r.Provider = "broken" })
	rec := e.callback(strings.Replace(l.target, "/callback/github", "/callback/broken", 1), l.cookie)
	wantErrorResult(t, rec, oidc.ModeQuery, "temporarily_unavailable", "st-1")
}

// Covers: FR-05 (part)
func TestCallbackStoreAndMethodFailures(t *testing.T) {
	t.Run("a busy store is a 503 page, any other failure a 500 page", func(t *testing.T) {
		for _, tt := range []struct {
			err    error
			status int
		}{{store.ErrUnavailable, 503}, {context.DeadlineExceeded, 500}} {
			e := newAuthzEnv(t, "github")
			l := e.begin(t, "github", goodRequest("provider", "github"))
			e.fs.FailRead = tt.err
			rec := e.callback(l.target, l.cookie)
			if rec.Code != tt.status || rec.Header().Get("Location") != "" {
				t.Errorf("%v: status %d, Location %q", tt.err, rec.Code, rec.Header().Get("Location"))
			}
		}
	})
	t.Run("a realm the store does not know has no logins", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		l := e.begin(t, "github", goodRequest("provider", "github"))
		e.fs.Fail("Realms.Find", store.ErrNotFound)
		wantPageRefusal(t, e.callback(l.target, l.cookie))
	})
	t.Run("a realm lookup that fails is a 500 page", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		l := e.begin(t, "github", goodRequest("provider", "github"))
		e.fs.Fail("Realms.Find", context.DeadlineExceeded)
		if rec := e.callback(l.target, l.cookie); rec.Code != 500 {
			t.Errorf("status %d", rec.Code)
		}
	})
	t.Run("only GET is accepted", func(t *testing.T) {
		e := newAuthzEnv(t, "github")
		req := httptest.NewRequest("PUT", "/main/callback/github", nil)
		rec := httptest.NewRecorder()
		e.rt.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status %d", rec.Code)
		}
	})
}

// appleLogin is a login at the Apple mock, which answers with a form POST.
type appleLogin struct {
	login
	posted url.Values // what Apple's page posts to the callback
}

// beginApple starts an Apple login and returns what the provider's page
// posts, as the browser would carry it from another site.
func (e *authzEnv) beginApple(t *testing.T, m int) appleLogin {
	t.Helper()
	e.apple.SetSecretCheck(func(string) error { return nil }) // the secret is a generated JWT
	c := modeClients[m]
	rec := e.get(goodRequest("provider", "apple", "client_id", c.client, "redirect_uri", c.uri))
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize: status %d, body %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("authorize set %d cookies", len(cookies))
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rec.Header().Get("Location"), nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	posted := url.Values{}
	for _, f := range hiddenField.FindAllStringSubmatch(b.String(), -1) {
		posted.Set(html.UnescapeString(f[1]), html.UnescapeString(f[2]))
	}
	return appleLogin{login: login{state: posted.Get("state"), cookie: cookies[0], mode: c.mode, idp: e.apple}, posted: posted}
}

// post sends the form to the callback path as Apple's page does: from another
// site, so without any cookie.
func (e *authzEnv) postCallback(path string, form url.Values) *httptest.ResponseRecorder {
	return e.do("POST", path, form)
}

// Covers: FR-05 (part), SEC-08 (part)
// Acceptance: Apple callback (part)
func TestAppleCallbackHandoff(t *testing.T) {
	t.Run("the POST needs no cookie and the GET with the cookie continues the login", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		l := e.beginApple(t, 0)
		if l.cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("the state cookie is SameSite %v, want Lax", l.cookie.SameSite)
		}
		rec := e.postCallback("/main/callback/apple", l.posted)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status %d, want 303; %s", rec.Code, rec.Body)
		}
		loc := mustURL(t, rec.Header().Get("Location"))
		if loc.Path != "/main/callback/apple/continue" || len(loc.Query().Get("id")) < 22 || loc.Query().Get("state") != l.state {
			t.Fatalf("Location %s", loc)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("the POST set cookies: %v", rec.Header().Values("Set-Cookie"))
		}
		if e.apple.TokenCalls() != 0 {
			t.Error("the POST exchanged the code")
		}
		got := e.callback(loc.RequestURI(), l.cookie)
		wantCookieDeleted(t, got, l.login)
		if n := e.apple.TokenCalls(); n != 1 {
			t.Errorf("%d code exchanges after the GET, want 1", n)
		}
	})
	t.Run("a deadlock once in the continue is run again and the login completes", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		l := e.beginApple(t, 0)
		rec := e.postCallback("/main/callback/apple", l.posted)
		loc := mustURL(t, rec.Header().Get("Location"))
		e.fs.AbortRuns(1, &pgconn.PgError{Code: "40P01"})
		got := e.callback(loc.RequestURI(), l.cookie)
		wantCookieDeleted(t, got, l.login)
		if n := e.apple.TokenCalls(); n != 1 {
			t.Errorf("%d code exchanges after the aborted continue, want 1", n)
		}
	})
	t.Run("a posted cancel reaches the adapter after the 303", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		e.apple.SetAuthorizeError("user_cancelled_authorize")
		l := e.beginApple(t, 1)
		loc := e.postCallback("/main/callback/apple", l.posted).Header().Get("Location")
		wantErrorResult(t, e.callback(loc, l.cookie), oidc.ModeFragment, "access_denied", "st-1")
		if e.apple.TokenCalls() != 0 {
			t.Error("a cancel was exchanged")
		}
	})
	// The answer each continue of a login gets: the error page for a login that
	// has completed, an access_denied redirect for the rest.
	const (
		wantErrorPage    = "the error page"
		wantAccessDenied = "access_denied"
	)
	t.Run("a replay of a completed login gets the error page, expiry, a missing cookie and bad ids are access_denied", func(t *testing.T) {
		for _, tt := range []struct {
			name      string
			run       func(e *authzEnv, l appleLogin, loc string) *httptest.ResponseRecorder
			want      string // wantErrorPage or wantAccessDenied
			exchanges int    // code exchanges at Apple after the continue
		}{
			{"replay of a completed login", func(e *authzEnv, l appleLogin, loc string) *httptest.ResponseRecorder {
				e.callback(loc, l.cookie) // the first continue completes the login
				return e.callback(loc, l.cookie)
			}, wantErrorPage, 1},
			{"expired id", func(e *authzEnv, l appleLogin, loc string) *httptest.ResponseRecorder {
				e.clk.Advance(60 * time.Second)
				return e.callback(loc, l.cookie)
			}, wantAccessDenied, 0},
			{"no cookie", func(e *authzEnv, l appleLogin, loc string) *httptest.ResponseRecorder {
				return e.callback(loc)
			}, wantAccessDenied, 0},
			{"unknown id", func(e *authzEnv, l appleLogin, loc string) *httptest.ResponseRecorder {
				return e.callback(strings.Replace(loc, "id=", "id=x", 1), l.cookie)
			}, wantAccessDenied, 0},
			{"no id", func(e *authzEnv, l appleLogin, loc string) *httptest.ResponseRecorder {
				return e.callback("/main/callback/apple/continue?state="+l.state, l.cookie)
			}, wantAccessDenied, 0},
		} {
			t.Run(tt.name, func(t *testing.T) {
				e := newAuthzEnv(t, "github", "apple")
				e.apple.SetUser(ann("ann@example.com"))
				l := e.beginApple(t, 2)
				loc := e.postCallback("/main/callback/apple", l.posted).Header().Get("Location")
				rec := tt.run(e, l, loc)
				switch tt.want {
				case wantErrorPage:
					wantPageRefusal(t, rec)
				case wantAccessDenied:
					wantErrorResult(t, rec, oidc.ModeFormPost, "access_denied", "st-1")
				default:
					t.Fatalf("unknown answer %q", tt.want)
				}
				wantCookieDeleted(t, rec, l.login)
				if n := e.apple.TokenCalls(); n != tt.exchanges {
					t.Errorf("%d code exchanges, want %d", n, tt.exchanges)
				}
			})
		}
	})
	t.Run("values stored for another state are refused", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		l := e.beginApple(t, 0)
		other := e.beginApple(t, 0)
		loc := mustURL(t, e.postCallback("/main/callback/apple", other.posted).Header().Get("Location"))
		q := loc.Query()
		q.Set("state", l.state) // the id of one login with the state of another
		rec := e.callback(loc.Path+"?"+q.Encode(), l.cookie)
		wantErrorResult(t, rec, oidc.ModeQuery, "access_denied", "st-1")
		if e.apple.TokenCalls() != 0 {
			t.Error("a mismatched handoff was exchanged")
		}
	})
	t.Run("a POST without a state shows the page and a bad form is refused", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		wantPageRefusal(t, e.postCallback("/main/callback/apple", url.Values{"code": {"c"}}))
		rec := e.do("POST", "/main/callback/apple", nil)
		wantPageRefusal(t, rec)
	})
	t.Run("the handoff does not keep error_description", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		l := e.beginApple(t, 0)
		l.posted.Set("error_description", "secret words")
		var payload string
		loc := e.postCallback("/main/callback/apple", l.posted).Header().Get("Location")
		err := e.st.Write(context.Background(), func(tx store.Tx) error {
			h, err := tx.Handoffs().Take(context.Background(), secure.HashOf(mustURL(t, loc).Query().Get("id")), e.clk.Now())
			payload = h.Payload
			return err
		})
		if err != nil || strings.Contains(payload, "secret") || !strings.Contains(payload, l.state) {
			t.Errorf("payload %q, err %v", payload, err)
		}
	})
	t.Run("only GET reaches continue", func(t *testing.T) {
		e := newAuthzEnv(t, "apple")
		rec := e.do("POST", "/main/callback/apple/continue", url.Values{})
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status %d", rec.Code)
		}
	})
	t.Run("a store failure on the POST is a 500 page", func(t *testing.T) {
		e := newAuthzEnv(t, "apple")
		l := e.beginApple(t, 0)
		e.fs.FailWrite = context.DeadlineExceeded
		if rec := e.postCallback("/main/callback/apple", l.posted); rec.Code != 500 {
			t.Errorf("status %d", rec.Code)
		}
	})
}

// handoffRows counts the handoffs in the store. DeleteExpired with a time after
// every handoff's expiry counts them all, and the write is rolled back so the
// count changes nothing.
func handoffRows(t *testing.T, e *authzEnv) int64 {
	t.Helper()
	errCount := errors.New("count only")
	var n int64
	err := e.st.Write(context.Background(), func(tx store.Tx) error {
		var err error
		n, err = tx.Handoffs().DeleteExpired(context.Background(), e.clk.Now().Add(time.Hour))
		if err != nil {
			return err
		}
		return errCount
	})
	if !errors.Is(err, errCount) {
		t.Fatalf("counting the handoffs: %v", err)
	}
	return n
}

// Covers: SEC-23
// Acceptance: Posted callback checks
func TestPostedCallbackChecks(t *testing.T) {
	// refused posts a form to a callback path and checks that the answer is the
	// expired-request page and that nothing was stored.
	refused := func(t *testing.T, e *authzEnv, path string, form url.Values) {
		t.Helper()
		wantPageRefusal(t, e.postCallback(path, form))
		if n := handoffRows(t, e); n != 0 {
			t.Errorf("%d handoffs stored, want 0", n)
		}
		if n := e.apple.TokenCalls(); n != 0 {
			t.Errorf("%d code exchanges at apple, want 0", n)
		}
	}
	t.Run("an unknown state", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		refused(t, e, "/main/callback/apple", url.Values{"code": {"c"}, "state": {"unknown"}})
	})
	t.Run("an expired login", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		l := e.beginApple(t, 0)
		e.clk.Advance(10 * time.Minute) // login_timeout
		refused(t, e, "/main/callback/apple", l.posted)
	})
	t.Run("a login of another realm", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		l := e.beginApple(t, 0)
		refused(t, e, "/closed/callback/apple", l.posted)
	})
	// The trusted provider stands in for Google: a generic provider that does
	// not return by form POST.
	t.Run("a login of another provider on the Apple path", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple", "trusted")
		l := e.begin(t, "trusted", goodRequest("provider", "trusted"))
		refused(t, e, "/main/callback/apple", url.Values{"code": {"c"}, "id_token": {"x"}, "state": {l.state}})
	})
	t.Run("a login of a provider that does not post on its path", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple", "trusted")
		l := e.begin(t, "trusted", goodRequest("provider", "trusted"))
		refused(t, e, "/main/callback/trusted", url.Values{"code": {"c"}, "state": {l.state}})
	})
	t.Run("a store failure reading the login", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		l := e.beginApple(t, 0)
		e.fs.FailRead = store.ErrUnavailable
		if rec := e.postCallback("/main/callback/apple", l.posted); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status %d, want 503", rec.Code)
		}
		e.fs.FailRead = nil
		if n := handoffRows(t, e); n != 0 {
			t.Errorf("%d handoffs stored, want 0", n)
		}
	})
	t.Run("two posts for one login", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		e.apple.SetUser(ann("ann@example.com"))
		l := e.beginApple(t, 0)
		first := mustURL(t, e.postCallback("/main/callback/apple", l.posted).Header().Get("Location"))
		second := mustURL(t, e.postCallback("/main/callback/apple", l.posted).Header().Get("Location"))
		if n := handoffRows(t, e); n != 1 {
			t.Fatalf("%d handoffs for one login, want 1", n)
		}
		// The first id was replaced, so its continue is refused.
		wantErrorResult(t, e.callback(first.RequestURI(), l.cookie), oidc.ModeQuery, "access_denied", "st-1")
		rec := e.callback(second.RequestURI(), l.cookie)
		if rec.Code != http.StatusFound {
			t.Fatalf("second continue: status %d, body %s", rec.Code, rec.Body)
		}
		if q := mustURL(t, rec.Header().Get("Location")).Query(); q.Get("code") == "" || q.Get("error") != "" {
			t.Errorf("second continue did not complete the login: %v", q)
		}
		if n := e.apple.TokenCalls(); n != 1 {
			t.Errorf("%d code exchanges, want 1", n)
		}
	})
}

// RFC 7636's example verifier of the challenge in goodRequest.
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// ann signs in the mock providers as Ann, with a verified address.
func ann(email string) mockidp.User {
	return mockidp.User{
		Sub: "42", Name: "Ann Lee", Email: email, EmailVerified: true,
		Emails: []mockidp.Email{{Email: email, Primary: true, Verified: true}},
	}
}

// exchange trades the code of a delivered result at the token service, as the
// client would, and fails the test when the code is no good.
func (e *authzEnv) exchange(t *testing.T, got url.Values, client, uri string) *token.Grant {
	t.Helper()
	snap := authzSource(t).Current()
	realm, _ := snap.Realm("main")
	g, err := e.codes.Exchange(context.Background(), token.ExchangeInput{
		Realm: realm, Client: realm.Clients[config.ClientID(client)], Code: got.Get("code"), RedirectURI: uri, Verifier: verifier,
	})
	if err != nil {
		t.Fatalf("the delivered code does not work: %v", err)
	}
	return g
}

// userOf returns the stored user of a provider identity.
func (e *authzEnv) userOf(t *testing.T, prov, sub string) store.User {
	t.Helper()
	var u store.User
	err := e.st.Read(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(context.Background(), "main")
		if err != nil {
			return err
		}
		ident, err := tx.Identities().Find(context.Background(), rid, config.ProviderKey(prov), sub)
		if err != nil {
			return err
		}
		u, err = tx.Users().Get(context.Background(), rid, ident.UserID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Covers: FR-06 (part), SEC-19 (part)
// Acceptance: Response modes
func TestCallbackDeliversTheCodeInEveryResponseMode(t *testing.T) {
	cases := []struct {
		name   string
		client string
		uri    string
		mode   string // the request's response_mode; empty leaves the client's
		want   oidc.ResponseMode
	}{
		{"query", "web", "https://app.example.com/callback", "", oidc.ModeQuery},
		{"fragment", "frag", "https://frag.example.com/callback", "", oidc.ModeFragment},
		{"form_post", "posting", "https://post.example.com/callback", "", oidc.ModeFormPost},
		{"the request's mode wins over a query client's", "web", "https://app.example.com/callback", "fragment", oidc.ModeFragment},
		{"the request's mode wins over a fragment client's", "frag", "https://frag.example.com/callback", "form_post", oidc.ModeFormPost},
		{"the request's mode wins over a form_post client's", "posting", "https://post.example.com/callback", "query", oidc.ModeQuery},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := newAuthzEnv(t, "corp")
			e.idp.SetUser(ann("ann@example.com"))
			l := e.begin(t, "corp", goodRequest("provider", "corp", "client_id", tt.client, "redirect_uri", tt.uri, "response_mode", orDash(tt.mode)))
			rec := e.callback(l.target, l.cookie)
			wantCookieDeleted(t, rec, l)
			got := result(t, rec, tt.want)
			if got.Get("state") != "st-1" || got.Get("iss") != issuer || got.Has("error") {
				t.Errorf("result %v", got)
			}
			if g := e.exchange(t, got, tt.client, tt.uri); g.AccessToken == "" {
				t.Error("no access token")
			}
			if e.idp.TokenCalls() != 1 {
				t.Errorf("%d code exchanges", e.idp.TokenCalls())
			}
		})
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Covers: FR-05 (part)
// Acceptance: Provider timeout
func TestCallbackProviderTimeout(t *testing.T) {
	e := newAuthzEnv(t, "slow")
	e.gh.SetUser(ann("ann@example.com"))
	l := e.begin(t, "slow", goodRequest("provider", "slow"))
	e.gh.Block()
	rec := e.callback(l.target, l.cookie)
	e.gh.Unblock()
	wantErrorResult(t, rec, oidc.ModeQuery, "temporarily_unavailable", "st-1")
	if n := e.gh.TokenCalls(); n != 1 {
		t.Errorf("%d code exchanges, want 1 (no retry)", n)
	}
}

// Covers: FR-22 (part)
// Acceptance: Apple name
func TestCallbackAppleNameIsKept(t *testing.T) {
	e := newAuthzEnv(t, "apple")
	signIn := func(u mockidp.User) {
		t.Helper()
		e.apple.SetUser(u)
		l := e.beginApple(t, 0)
		loc := e.postCallback("/main/callback/apple", l.posted).Header().Get("Location")
		got := result(t, e.callback(loc, l.cookie), oidc.ModeQuery)
		if got.Get("code") == "" {
			t.Fatalf("no code: %v", got)
		}
	}
	signIn(ann("ann@example.com")) // the first authorization carries the name
	if u := e.userOf(t, "apple", "42"); u.Name != "Ann Lee" {
		t.Fatalf("first login stored name %q", u.Name)
	}
	second := ann("ann@example.com")
	second.Name = "" // later authorizations carry none
	signIn(second)
	if u := e.userOf(t, "apple", "42"); u.Name != "Ann Lee" {
		t.Errorf("second login left name %q", u.Name)
	}
}

// Covers: FR-12 (part), SEC-04 (part)
// Acceptance: Auto-link (part)
func TestCallbackLinksAnotherProviderOverHTTP(t *testing.T) {
	e := newAuthzEnv(t, "trusted", "apple")
	e.idp.SetUser(ann("ann@gmail.com"))
	l := e.begin(t, "trusted", goodRequest("provider", "trusted"))
	if got := result(t, e.callback(l.target, l.cookie), oidc.ModeQuery); got.Get("code") == "" {
		t.Fatalf("no code: %v", got)
	}
	apple := ann(" Ann@gmail.com ")
	apple.Sub = "apple-1"
	e.apple.SetUser(apple)
	al := e.beginApple(t, 0)
	loc := e.postCallback("/main/callback/apple", al.posted).Header().Get("Location")
	if got := result(t, e.callback(loc, al.cookie), oidc.ModeQuery); got.Get("code") == "" {
		t.Fatalf("no code: %v", got)
	}
	if a, b := e.userOf(t, "trusted", "42"), e.userOf(t, "apple", "apple-1"); a.ID != b.ID {
		t.Errorf("two users: %s and %s", a.ID, b.ID)
	}
}

// Covers: FR-02 (part)
// Acceptance: Login hints (part)
func TestCallbackMaxAge(t *testing.T) {
	for _, tt := range []struct {
		name     string
		authTime time.Duration // before now; 0 leaves the claim out
		maxAge   string
		want     string
	}{
		{"older than max_age", time.Hour, "300", "login_required"},
		{"within max_age", time.Minute, "300", ""},
		{"no auth_time claim counts as now", 0, "300", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newAuthzEnv(t, "corp")
			u := ann("ann@example.com")
			if tt.authTime > 0 {
				u.AuthTime = testStart.Add(-tt.authTime)
			}
			e.idp.SetUser(u)
			l := e.begin(t, "corp", goodRequest("provider", "corp", "max_age", tt.maxAge))
			rec := e.callback(l.target, l.cookie)
			if tt.want == "" {
				if got := result(t, rec, oidc.ModeQuery); got.Get("code") == "" {
					t.Errorf("no code: %v", got)
				}
				return
			}
			wantErrorResult(t, rec, oidc.ModeQuery, tt.want, "st-1")
		})
	}
}

// Covers: FR-05 (part), SEC-14 (part)
func TestCallbackDisabledUserAndFailures(t *testing.T) {
	t.Run("a disabled user gets access_denied", func(t *testing.T) {
		e := newAuthzEnv(t, "corp")
		e.idp.SetUser(ann("ann@example.com"))
		l := e.begin(t, "corp", goodRequest("provider", "corp"))
		if got := result(t, e.callback(l.target, l.cookie), oidc.ModeQuery); got.Get("code") == "" {
			t.Fatalf("no code: %v", got)
		}
		u := e.userOf(t, "corp", "42")
		u.DisabledAt = e.clk.Now()
		if err := e.st.Write(context.Background(), func(tx store.Tx) error { return tx.Users().Update(context.Background(), u) }); err != nil {
			t.Fatal(err)
		}
		l = e.begin(t, "corp", goodRequest("provider", "corp"))
		wantErrorResult(t, e.callback(l.target, l.cookie), oidc.ModeQuery, "access_denied", "st-1")
	})
	t.Run("a provider that sends no subject is refused", func(t *testing.T) {
		e := newAuthzEnv(t, "corp")
		e.idp.SetUser(mockidp.User{Sub: "", Email: "a@example.com", EmailVerified: true})
		l := e.begin(t, "corp", goodRequest("provider", "corp"))
		rec := e.callback(l.target, l.cookie)
		if got := result(t, rec, oidc.ModeQuery); got.Get("error") == "" || got.Has("code") {
			t.Errorf("result %v", got)
		}
	})
	for _, op := range []string{"Users.Create", "AuthCodes.Create"} {
		t.Run(op+" failing is a server_error", func(t *testing.T) {
			e := newAuthzEnv(t, "corp")
			e.idp.SetUser(ann("ann@example.com"))
			l := e.begin(t, "corp", goodRequest("provider", "corp"))
			e.fs.Fail(op, context.DeadlineExceeded)
			wantErrorResult(t, e.callback(l.target, l.cookie), oidc.ModeQuery, "server_error", "st-1")
		})
	}
}

// Covers: SEC-19
func TestEveryAuthorizationResponseCarriesIss(t *testing.T) {
	for i, m := range modeClients {
		t.Run(m.name, func(t *testing.T) {
			e := newAuthzEnv(t, "github", "corp")
			e.gh.SetUser(ann("ann@example.com"))
			e.idp.SetUser(ann("ann@example.com"))
			iss := func(rec *httptest.ResponseRecorder) string { return result(t, rec, m.mode).Get("iss") }

			l := e.beginMode(t, "corp", i)
			if got := iss(e.callback(l.target, l.cookie)); got != issuer {
				t.Errorf("success: iss %q", got)
			}
			l = e.beginMode(t, "corp", i)
			if got := iss(e.callback(l.target)); got != issuer { // no cookie
				t.Errorf("cookie failure: iss %q", got)
			}
			if got := iss(e.callback(asProvider(l.target, "github"), l.cookie)); got != issuer {
				t.Errorf("mix-up: iss %q", got)
			}
			e.idp.SetAuthorizeError("access_denied")
			l = e.beginMode(t, "corp", i)
			if got := iss(e.callback(l.target, l.cookie)); got != issuer {
				t.Errorf("cancel: iss %q", got)
			}
			if got := iss(e.callback(l.target, l.cookie)); got != issuer {
				t.Errorf("replay: iss %q", got)
			}
		})
	}
}

// failing is an adapter whose exchange fails with an HTTP client error that
// carries a secret in its URL.
type failing struct{ provider.Provider }

func (f failing) Exchange(context.Context, provider.Callback, string, string) (provider.Identity, error) {
	return provider.Identity{}, &url.Error{Op: "Post", URL: "https://idp.example/token?code=SECRETCODE-unlikely-4711", Err: context.DeadlineExceeded}
}

// Covers: SEC-13 (part)
func TestCallbackLogsCleanProviderErrors(t *testing.T) {
	e := newAuthzEnv(t, "corp")
	l := e.begin(t, "corp", goodRequest("provider", "corp"))
	reg := tsrv.Registry{Registry: e.reg, Adapters: map[config.ProviderKey]provider.Provider{"corp": failing{}}}
	h := oidc.NewCallback(oidc.CallbackConfig{Registry: reg, Store: e.fs, Clock: e.clk, Log: e.log})
	e.rt = server.NewHandler(e.src, authzHandlers{&deliverHandlers{}, nil, h}, server.Middleware{Logger: e.log, Clock: e.clk})
	rec := e.callback(l.target, l.cookie)
	wantErrorResult(t, rec, oidc.ModeQuery, "server_error", "st-1")
	if !strings.Contains(e.logs.String(), "the provider login failed") {
		t.Fatalf("the failure is not logged:\n%s", e.logs)
	}
	if strings.Contains(e.logs.String(), "SECRETCODE-unlikely-4711") {
		t.Errorf("a secret reached the log:\n%s", e.logs)
	}
}

// A refresh token to keep with no encryption key cannot happen after config
// validation; if it does, the login fails and nothing is stored or logged.
//
// Covers: SEC-10 (part), SEC-13 (part)
func TestCallbackRefreshTokenWithoutBoxFailsTheLogin(t *testing.T) {
	e := newAuthzEnv(t, "github", "apple")
	e.apple.SetUser(mockidp.User{Sub: "apple-1", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
	l := e.beginApple(t, 0)
	users := user.NewService(e.fs, audit.NewWriter(e.fs, e.log, e.clk, secure.Default), e.log, e.clk, secure.Default)
	h := oidc.NewCallback(oidc.CallbackConfig{Registry: e.reg, Store: e.fs, Clock: e.clk, Log: e.log, Users: users, Codes: e.codes})
	e.rt = server.NewHandler(e.src, authzHandlers{&deliverHandlers{}, nil, h}, server.Middleware{Logger: e.log, Clock: e.clk})
	loc := e.postCallback("/main/callback/apple", l.posted).Header().Get("Location")
	rec := e.callback(loc, l.cookie)
	wantErrorResult(t, rec, oidc.ModeQuery, "server_error", "st-1")
	got := result(t, rec, oidc.ModeQuery)
	for _, leak := range []string{"key", "box", "seal", "encrypt"} {
		if strings.Contains(strings.ToLower(got.Get("error_description")), leak) {
			t.Errorf("error_description %q leaks %q", got.Get("error_description"), leak)
		}
	}
	rt := e.apple.RefreshToken()
	if rt == "" {
		t.Fatal("the mock gave no refresh token")
	}
	if strings.Contains(e.logs.String(), rt) {
		t.Errorf("the refresh token reached the log:\n%s", e.logs)
	}
	err := e.st.Read(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(context.Background(), "main")
		if err != nil {
			return err
		}
		_, err = tx.Identities().Find(context.Background(), rid, "apple", "apple-1")
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("an identity was stored: %v", err)
	}
}

// visitProvider sends the browser to a provider URL and returns the URL the
// provider redirects it back to.
func visitProvider(t *testing.T, providerURL string) *url.URL {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, providerURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return mustURL(t, resp.Header.Get("Location"))
}

// providerTargets starts a login through /authorize and then visits the
// provider's authorize URL n times, so that the one login has n provider codes
// with the same state. It returns the state cookie and the n callback targets.
func (e *authzEnv) providerTargets(t *testing.T, v url.Values, n int) (*http.Cookie, []string) {
	t.Helper()
	rec := e.get(v)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize: status %d, body %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("authorize set %d cookies", len(cookies))
	}
	targets := make([]string, 0, n)
	for i := 0; i < n; i++ {
		targets = append(targets, visitProvider(t, rec.Header().Get("Location")).RequestURI())
	}
	return cookies[0], targets
}

// loginStored reports whether the auth request of the state is still stored.
func (e *authzEnv) loginStored(t *testing.T, state string) bool {
	t.Helper()
	var found bool
	err := e.st.Read(context.Background(), func(tx store.Tx) error {
		_, err := tx.AuthRequests().Get(context.Background(), store.AuthRequestID(state))
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		found = err == nil
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// codeRows counts the login codes in the store. DeleteExpired with a time after
// every code's expiry counts them all, and the write is rolled back so the
// count changes nothing.
func (e *authzEnv) codeRows(t *testing.T) int64 {
	t.Helper()
	errCount := errors.New("count only")
	var n int64
	err := e.st.Write(context.Background(), func(tx store.Tx) error {
		var err error
		n, err = tx.AuthCodes().DeleteExpired(context.Background(), e.clk.Now().Add(time.Hour))
		if err != nil {
			return err
		}
		return errCount
	})
	if !errors.Is(err, errCount) {
		t.Fatalf("counting the codes: %v", err)
	}
	return n
}

// Covers: SEC-28
// Acceptance: Login single use
func TestLoginCompletesOnce(t *testing.T) {
	t.Run("a second callback with the same state, cookie and a new provider code gets the error page and no code", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		e.gh.SetUser(ann("ann@example.com"))
		cookie, targets := e.providerTargets(t, goodRequest("provider", "github"), 2)
		if got := result(t, e.callback(targets[0], cookie), oidc.ModeQuery); !got.Has("code") {
			t.Fatalf("the first callback gave no code: %v", got)
		}
		codes, exchanges := e.codeRows(t), e.gh.TokenCalls()
		rec := e.callback(targets[1], cookie)
		wantPageRefusal(t, rec)
		wantCookieDeleted(t, rec, login{cookie: cookie})
		if n := e.codeRows(t); n != codes {
			t.Errorf("%d codes after the second callback, want %d", n, codes)
		}
		if n := e.gh.TokenCalls(); n != exchanges {
			t.Errorf("the second callback exchanged the code: %d calls, want %d", n, exchanges)
		}
	})
	t.Run("two callbacks at once issue one code", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "corp")
		e.gh.SetUser(ann("ann@example.com"))
		// An earlier login creates the user, so that the two callbacks only
		// read it.
		warm := e.begin(t, "github", goodRequest("provider", "github"))
		if got := result(t, e.callback(warm.target, warm.cookie), oidc.ModeQuery); !got.Has("code") {
			t.Fatalf("the warm-up login gave no code: %v", got)
		}
		cookie, targets := e.providerTargets(t, goodRequest("provider", "github"), 2)
		codes, base := e.codeRows(t), e.gh.TokenCalls()
		// Both callbacks read the login and are held at the provider's token
		// endpoint; released together, both reach the code issue.
		e.gh.Block()
		defer e.gh.Unblock() // a failing test must not leave a callback held
		answers := make(chan *httptest.ResponseRecorder, len(targets))
		for _, target := range targets {
			go func(target string) { answers <- e.callback(target, cookie) }(target)
		}
		// Wait until both reached the token endpoint. An answer before that is a
		// callback that ended early, and too many turns is a callback stuck
		// elsewhere: both fail the test instead of hanging it.
		for spins := 0; e.gh.TokenCalls() < base+len(targets); spins++ {
			if spins > 1_000_000 {
				t.Fatalf("the callbacks did not reach the provider: %d token calls", e.gh.TokenCalls()-base)
			}
			select {
			case rec := <-answers:
				t.Fatalf("a callback answered %d before reaching the provider: %s", rec.Code, rec.Body)
			default:
			}
			runtime.Gosched()
		}
		e.gh.Unblock()
		var issued, refused int
		for range targets {
			rec := <-answers
			if rec.Code == http.StatusFound {
				if !result(t, rec, oidc.ModeQuery).Has("code") {
					t.Errorf("a 302 without a code: %s", rec.Header().Get("Location"))
				}
				issued++
				continue
			}
			wantPageRefusal(t, rec)
			refused++
		}
		if issued != 1 || refused != 1 {
			t.Fatalf("%d callbacks issued a code and %d got the error page, want 1 and 1", issued, refused)
		}
		if n := e.codeRows(t); n != codes+1 {
			t.Errorf("%d codes stored, want %d", n, codes+1)
		}
		if !strings.Contains(e.logs.String(), "the login was completed by another callback") {
			t.Errorf("the refused callback does not log why it was refused: %s", e.logs)
		}
	})
	t.Run("a replayed continue id of a completed Apple login gets the error page", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		e.apple.SetUser(ann("ann@example.com"))
		l := e.beginApple(t, 0)
		loc := e.postCallback("/main/callback/apple", l.posted).Header().Get("Location")
		if got := result(t, e.callback(loc, l.cookie), oidc.ModeQuery); !got.Has("code") {
			t.Fatalf("the continue of the login gave no code: %v", got)
		}
		codes := e.codeRows(t)
		rec := e.callback(loc, l.cookie)
		wantPageRefusal(t, rec)
		wantCookieDeleted(t, rec, l.login)
		if n := e.apple.TokenCalls(); n != 1 {
			t.Errorf("%d code exchanges, want 1", n)
		}
		if n := e.codeRows(t); n != codes {
			t.Errorf("%d codes after the replay, want %d", n, codes)
		}
	})
	t.Run("a replayed handoff of a failed Apple login still gets access_denied", func(t *testing.T) {
		e := newAuthzEnv(t, "github", "apple")
		e.apple.SetAuthorizeError("user_cancelled_authorize")
		l := e.beginApple(t, 2)
		loc := e.postCallback("/main/callback/apple", l.posted).Header().Get("Location")
		wantErrorResult(t, e.callback(loc, l.cookie), oidc.ModeFormPost, "access_denied", "st-1")
		wantErrorResult(t, e.callback(loc, l.cookie), oidc.ModeFormPost, "access_denied", "st-1")
		if !e.loginStored(t, l.state) {
			t.Error("the failed login was deleted")
		}
	})
}

// Covers: SEC-28 (part)
// Acceptance: Login single use (part)
func TestLoginCompletionFailureKeepsTheLogin(t *testing.T) {
	e := newAuthzEnv(t, "github")
	e.gh.SetUser(ann("ann@example.com"))
	l := e.begin(t, "github", goodRequest("provider", "github"))
	codes := e.codeRows(t)
	e.fs.Fail("AuthRequests.Delete", context.DeadlineExceeded)
	wantErrorResult(t, e.callback(l.target, l.cookie), oidc.ModeQuery, "server_error", "st-1")
	if n := e.codeRows(t); n != codes {
		t.Errorf("%d codes after a failed completion, want %d", n, codes)
	}
	if !e.loginStored(t, l.state) {
		t.Error("a failed completion deleted the login")
	}
}
