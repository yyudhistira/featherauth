package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/logscan"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/token"
)

// rwForm posts a form to a URL of the service as a new browser.
func rwForm(t *testing.T, e *server.Env, rawURL string, v url.Values, h http.Header) server.Response {
	t.Helper()
	hh := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	for k, x := range h {
		hh[k] = x
	}
	return e.NewClient().Request(t, http.MethodPost, rawURL, v.Encode(), hh)
}

// rwRefreshWorks reports whether the refresh token still gets new tokens.
func rwRefreshWorks(t *testing.T, e *server.Env, app server.App, rt string) bool {
	t.Helper()
	return e.NewClient().PostToken(t, server.RefreshForm(app, rt), nil).Code == http.StatusOK
}

// rwIdentity reports whether the realm still has the identity.
func rwIdentity(t *testing.T, e *server.Env, prov config.ProviderKey, sub string) bool {
	t.Helper()
	ctx := context.Background()
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		_, err = tx.Identities().Find(ctx, rid, prov, sub)
		return err
	})
	return err == nil
}

// rwFacebookLogin signs a Facebook user in and returns the grant.
func rwFacebookLogin(t *testing.T, e *server.Env, app server.App, sub string) *token.Grant {
	t.Helper()
	e.Mocks["facebook"].SetUser(mockidp.User{Sub: sub, Name: "Fay Lee", Email: sub + "@example.com"})
	return e.Exchange(t, app, e.NewClient().Login(t, server.Authorize(app, "facebook")))
}

var rwCode = regexp.MustCompile(`^[A-Za-z0-9]{22}$`)

// rwMetaAnswer checks Meta's 200 answer and returns its confirmation code.
func rwMetaAnswer(t *testing.T, status int, body string) string {
	t.Helper()
	var got map[string]string
	if status != http.StatusOK || json.Unmarshal([]byte(body), &got) != nil || !rwCode.MatchString(got["confirmation_code"]) ||
		got["url"] != server.Issuer+"/data-deletion?code="+got["confirmation_code"] {
		t.Fatalf("Meta's answer: %d %q", status, body)
	}
	return got["confirmation_code"]
}

// TestRoadmapItemsWiring wires the roadmap items together with no fakes
// but the clock and the identity providers: the revocation endpoint, sign out
// everywhere and Meta's data-deletion callback run against one service, in
// process; then the same endpoints answer in the real process of `serve`, with
// the real clock, so the wiring of cmd (the handlers, the confirmation codes,
// the Facebook adapter's clock and secret) is the one that ships. The logs of
// the in-process run are scanned for secrets at the end.
//
// Covers: FR-38 (part), FR-39 (part), FR-40 (part), SEC-13 (part), SEC-33 (part), SEC-34 (part)
func TestRoadmapItemsWiring(t *testing.T) {
	e := server.New(t)
	e.Reload(t, func(y string) string {
		return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n",
			"  web:\n    redirect_uris: [https://app.example.com/callback]\n    allow_session_management: true\n", 1)
	})
	web, frag := server.ClientQuery, server.ClientFragment
	var secrets []string
	keep := func(tk *token.Grant) *token.Grant {
		secrets = append(secrets, tk.AccessToken, tk.IDToken, tk.RefreshToken)
		return tk
	}

	t.Run("discovery lists the revocation endpoint", func(t *testing.T) {
		r := e.NewClient().Do(t, http.MethodGet, server.Issuer+"/.well-known/openid-configuration", nil)
		if !strings.Contains(r.Body, `"revocation_endpoint":"`+server.Issuer+`/revoke"`) {
			t.Errorf("discovery: %s", r.Body)
		}
	})

	t.Run("a refresh token is revoked by the revocation endpoint", func(t *testing.T) {
		tk := keep(e.Exchange(t, web, e.Login(t, web)))
		other := keep(e.Exchange(t, web, e.Login(t, web)))
		r := rwForm(t, e, server.Issuer+"/revoke", url.Values{"token": {tk.RefreshToken}, "client_id": {web.ID}}, nil)
		if r.Code != http.StatusOK || r.Body != "" || r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("revoke: %d %v %q", r.Code, r.Header, r.Body)
		}
		if rwRefreshWorks(t, e, web, tk.RefreshToken) {
			t.Error("the revoked session still refreshes")
		}
		if !rwRefreshWorks(t, e, web, other.RefreshToken) {
			t.Error("another session was revoked")
		}
	})

	t.Run("sign out everywhere ends the sessions of every client", func(t *testing.T) {
		a := keep(e.Exchange(t, web, e.Login(t, web)))
		f := keep(e.Exchange(t, frag, e.Login(t, frag)))
		r := e.NewClient().Request(t, http.MethodPost, server.Issuer+"/logout", url.Values{"all_sessions": {"true"}}.Encode(),
			http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Authorization": {"Bearer " + a.AccessToken}})
		if r.Code != http.StatusNoContent || r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("sign out everywhere: %d %v %q", r.Code, r.Header, r.Body)
		}
		if rwRefreshWorks(t, e, web, a.RefreshToken) || rwRefreshWorks(t, e, frag, f.RefreshToken) {
			t.Error("a session survived")
		}
		// The client without the option is refused.
		g := keep(e.Exchange(t, frag, e.Login(t, frag)))
		r = e.NewClient().Request(t, http.MethodPost, server.Issuer+"/logout", url.Values{"all_sessions": {"true"}}.Encode(),
			http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Authorization": {"Bearer " + g.AccessToken}})
		if r.Code != http.StatusForbidden || r.Header.Get("WWW-Authenticate") != `Bearer error="insufficient_scope"` {
			t.Errorf("a client without the option: %d %v", r.Code, r.Header)
		}
		if !rwRefreshWorks(t, e, frag, g.RefreshToken) {
			t.Error("the refused request revoked the session")
		}
	})

	t.Run("Meta's callback deletes the user and answers with a code", func(t *testing.T) {
		tk := keep(rwFacebookLogin(t, e, web, "fb-1"))
		sr := mockidp.SignedRequest(e.Mocks["facebook"].ClientSecret(), map[string]any{
			"algorithm": "HMAC-SHA256", "issued_at": e.Clock.Now().Unix(), "user_id": "fb-1",
		})
		secrets = append(secrets, sr, e.Mocks["facebook"].ClientSecret())
		r := rwForm(t, e, server.Issuer+"/events/facebook", url.Values{"signed_request": {sr}}, nil)
		code := rwMetaAnswer(t, r.Code, r.Body)
		if rwIdentity(t, e, "facebook", "fb-1") || rwRefreshWorks(t, e, web, tk.RefreshToken) {
			t.Error("the user or its session is still there")
		}
		page := e.NewClient().Do(t, http.MethodGet, server.Issuer+"/data-deletion?code="+code, nil)
		if !strings.Contains(page.Body, "<code>"+code+"</code>") {
			t.Errorf("the page does not show the code: %s", page.Body)
		}
	})

	t.Run("the real process answers all three", func(t *testing.T) {
		tk := keep(e.Exchange(t, web, e.Login(t, web)))
		keep(rwFacebookLogin(t, e, web, "fb-2"))
		serviceConfigDir(t, e)
		p := startProcess(t, e.ConfigDir())
		addr := p.listening(t)
		client := &http.Client{Timeout: processLimit, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		do := func(method, path string, form url.Values) (int, http.Header, string) {
			t.Helper()
			var body io.Reader
			if form != nil {
				body = strings.NewReader(form.Encode())
			}
			req, err := http.NewRequestWithContext(t.Context(), method, "http://"+addr+path, body)
			if err != nil {
				t.Fatal(err)
			}
			if form != nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, resp.Header, string(b)
		}

		if code, _, body := do(http.MethodGet, "/main/.well-known/openid-configuration", nil); code != 200 || !strings.Contains(body, `"revocation_endpoint":"https://auth.example.com/main/revoke"`) {
			t.Errorf("discovery: %d %s", code, body)
		}
		// The revocation endpoint: the refresh token of the first session works
		// until it is revoked (its expiry is a month ahead of the fake clock).
		code, h, body := do(http.MethodPost, "/main/revoke", url.Values{"token": {tk.RefreshToken}, "client_id": {web.ID}})
		if code != 200 || body != "" || h.Get("Cache-Control") != "no-store" {
			t.Errorf("revoke: %d %v %q", code, h, body)
		}
		if code, _, _ := do(http.MethodPost, "/main/revoke", url.Values{"client_id": {web.ID}}); code != http.StatusBadRequest {
			t.Errorf("revoke without a token: %d, want 400", code)
		}
		if code, _, _ := do(http.MethodGet, "/main/revoke", nil); code != http.StatusMethodNotAllowed {
			t.Errorf("GET revoke: %d, want 405", code)
		}
		// Meta's callback, dated by the real clock the process runs on.
		// The process reads the app secret from the file of the configuration.
		file, err := os.ReadFile(filepath.Join(e.ConfigDir(), "secrets", "main", "facebook_secret"))
		if err != nil {
			t.Fatal(err)
		}
		secret := strings.TrimSuffix(string(file), "\n")
		sr := mockidp.SignedRequest(secret, map[string]any{
			"algorithm": "HMAC-SHA256", "issued_at": clock.Real().Now().Unix(), "user_id": "fb-2",
		})
		if code, h, body := do(http.MethodPost, "/main/events/facebook", url.Values{"signed_request": {"x" + sr}}); code != http.StatusBadRequest || h.Get("Cache-Control") != "no-store" {
			t.Errorf("a bad signed_request: %d %v %q", code, h, body)
		}
		code, _, body = do(http.MethodPost, "/main/events/facebook", url.Values{"signed_request": {sr}})
		confirmation := rwMetaAnswer(t, code, body)
		if rwIdentity(t, e, "facebook", "fb-2") {
			t.Error("the process did not delete the user")
		}
		if code, _, body := do(http.MethodGet, "/main/data-deletion?code="+confirmation, nil); code != 200 || !strings.Contains(body, "<code>"+confirmation+"</code>") {
			t.Errorf("the data-deletion page: %d %s", code, body)
		}
		if code, _, body := do(http.MethodGet, "/main/data-deletion?code=%3Cscript%3E", nil); code != 200 || strings.Contains(body, "<code>") {
			t.Errorf("the data-deletion page with a bad code: %d %s", code, body)
		}
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		if c := p.exitCode(t); c != 0 {
			t.Errorf("the service exited %d", c)
		}
		secrets = append(secrets, secret, sr)
	})

	t.Run("the logs of the run hold no secret", func(t *testing.T) {
		secrets = append(secrets, server.Verifier)
		logscan.WantClean(t, e, secrets...)
	})
}
