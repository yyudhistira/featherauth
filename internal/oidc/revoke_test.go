package oidc_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

const revokeURL = server.Issuer + "/revoke"

// revoke posts a form to the revocation endpoint from a new browser.
func revoke(t *testing.T, e *server.Env, v url.Values, h http.Header) server.Response {
	t.Helper()
	hh := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	for k, x := range h {
		hh[k] = x
	}
	return e.NewClient().Request(t, http.MethodPost, revokeURL, v.Encode(), hh)
}

// revokeForm is the form of a public client revoking token.
func revokeForm(app server.App, token string) url.Values {
	return url.Values{"token": {token}, "client_id": {app.ID}}
}

// wantRevokeAnswer checks the answer every revocation gets: 200, no body and
// the no-store headers.
func wantRevokeAnswer(t *testing.T, r server.Response) {
	t.Helper()
	if r.Code != http.StatusOK || r.Body != "" || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("status %d headers %v body %q, want 200 with an empty body and no-store", r.Code, r.Header, r.Body)
	}
}

// Covers: FR-38, SEC-34
// Acceptance: Revocation endpoint
func TestRevocationEndpoint(t *testing.T) {
	app := server.ClientQuery
	frag := server.ClientFragment
	t.Run("a refresh token of the client ends its session", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		next := wantTokens(t, refresh(t, e, app, tk.RefreshToken)) // a successor of the same session
		other := exchange(t, e, app)
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, next.RefreshToken), nil))
		wantRevoked(t, e, app, next.RefreshToken)
		wantAlive(t, e, app, other.RefreshToken)
	})
	t.Run("a rotated refresh token of the client also ends its session", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		next := wantTokens(t, refresh(t, e, app, tk.RefreshToken))
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, tk.RefreshToken), nil))
		if !refreshRevoked(t, e, next.RefreshToken) {
			t.Error("the session's successor token is not revoked")
		}
	})
	t.Run("an expired refresh token of the client also ends its session", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		e.Clock.Advance(721 * time.Hour) // past refresh_idle_lifetime (720 h)
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, tk.RefreshToken), nil))
		if !refreshRevoked(t, e, tk.RefreshToken) {
			t.Error("not revoked")
		}
	})
	t.Run("an access token of the client ends its session", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		next := wantTokens(t, refresh(t, e, app, tk.RefreshToken)) // the same session
		other := exchange(t, e, app)
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, tk.AccessToken), nil))
		wantRevoked(t, e, app, next.RefreshToken)
		wantAlive(t, e, app, other.RefreshToken)
	})
	t.Run("a refresh token of another client changes nothing", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		fr := exchange(t, e, frag)
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, fr.RefreshToken), nil))
		wantTokens(t, refresh(t, e, frag, fr.RefreshToken))
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("an access token of another client changes nothing", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		fr := exchange(t, e, frag)
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, fr.AccessToken), nil))
		wantTokens(t, refresh(t, e, frag, fr.RefreshToken))
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("an unknown token changes nothing", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, "not-a-token"), nil))
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("an ID token changes nothing", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, tk.IDToken), nil))
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("an expired access token changes nothing", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		e.Clock.Advance(time.Hour) // past the 15-minute access token lifetime
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, tk.AccessToken), nil))
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("a missing or empty token is invalid_request", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		wantError(t, revoke(t, e, url.Values{"client_id": {app.ID}}, nil), 400, "invalid_request")
		wantError(t, revoke(t, e, revokeForm(app, ""), nil), 400, "invalid_request")
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("a repeated token is invalid_request", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		v := url.Values{"token": {tk.RefreshToken, tk.RefreshToken}, "client_id": {app.ID}}
		wantError(t, revoke(t, e, v, nil), 400, "invalid_request")
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("a token_type_hint of any value steers only the order", func(t *testing.T) {
		for _, hint := range []string{"refresh_token", "access_token", "anything"} {
			e := server.New(t)
			tk := exchange(t, e, app)
			next := wantTokens(t, refresh(t, e, app, tk.RefreshToken))
			v := revokeForm(app, next.AccessToken)
			v.Set("token_type_hint", hint)
			wantRevokeAnswer(t, revoke(t, e, v, nil))
			wantRevoked(t, e, app, next.RefreshToken)
		}
	})
	t.Run("the first of two token_type_hint values counts", func(t *testing.T) {
		// With the hint access_token first, a refresh token lookup is not made,
		// so a failing lookup does not matter; with refresh_token first it does.
		for _, row := range []struct {
			hints  []string
			status int
		}{
			{[]string{"access_token", "refresh_token"}, 200},
			{[]string{"refresh_token", "access_token"}, 500},
		} {
			e := server.New(t)
			tk := exchange(t, e, app)
			e.Faults.Fail("Refresh.FindByHash", fmt.Errorf("disk on fire"))
			v := revokeForm(app, tk.AccessToken)
			v["token_type_hint"] = row.hints
			r := revoke(t, e, v, nil)
			e.Faults.Fail("Refresh.FindByHash", nil)
			if r.Code != row.status {
				t.Fatalf("hints %v: status %d, want %d", row.hints, r.Code, row.status)
			}
			if revoked := refreshRevoked(t, e, tk.RefreshToken); revoked != (row.status == 200) {
				t.Errorf("hints %v: revoked %v", row.hints, revoked)
			}
		}
	})
	t.Run("the access token of a disabled user is still revoked", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		e.SetDisabled(t, true)
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, tk.AccessToken), nil))
		if !refreshRevoked(t, e, tk.RefreshToken) {
			t.Error("not revoked")
		}
	})
	t.Run("one information line per request, without the token", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		fr := exchange(t, e, frag)
		for _, tok := range []string{tk.AccessToken, tk.RefreshToken, tk.RefreshToken, fr.RefreshToken, "not-a-token"} {
			e.Logs.Reset()
			wantRevokeAnswer(t, revoke(t, e, revokeForm(app, tok), nil))
			logs := e.Logs.String()
			if n := strings.Count(logs, `"msg":"revocation"`); n != 1 {
				t.Errorf("%d revocation lines, want 1: %s", n, logs)
			}
			if !strings.Contains(logs, `"msg":"revocation"`) || strings.Contains(logs, tok) {
				t.Errorf("the log holds the token or no line: %s", logs)
			}
			for _, line := range strings.Split(logs, "\n") {
				if strings.Contains(line, `"msg":"revocation"`) && !strings.Contains(line, `"level":"INFO"`) {
					t.Errorf("not an information line: %s", line)
				}
			}
		}
	})
	t.Run("every error answer carries no-store", func(t *testing.T) {
		e := server.New(t)
		conf := server.ClientConfidential
		ctk := exchangeConfidential(t, e, conf)
		wantNoStore := func(name string, r server.Response, status int) {
			t.Helper()
			if r.Code != status || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
				t.Errorf("%s: status %d (want %d) headers %v", name, r.Code, status, r.Header)
			}
		}
		wantNoStore("400", revoke(t, e, revokeForm(app, ""), nil), 400)
		wantNoStore("401", revoke(t, e, url.Values{"token": {ctk.RefreshToken}}, basic(conf.ID, "nope")), 401)
		e.Faults.Fail("Refresh.FindByHash", store.ErrUnavailable)
		wantNoStore("503", revoke(t, e, revokeForm(app, ctk.RefreshToken), nil), 503)
		e.Faults.Fail("Refresh.FindByHash", nil)
	})
	t.Run("a wrong client secret is answered as at the token endpoint", func(t *testing.T) {
		e := server.New(t)
		conf := server.ClientConfidential
		tk := exchangeConfidential(t, e, conf)
		form := url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tk.RefreshToken},
			"client_id": {conf.ID}, "client_secret": {"nope"},
		}
		want := post(t, e, form, nil)
		got := revoke(t, e, url.Values{"token": {tk.RefreshToken}, "client_id": {conf.ID}, "client_secret": {"nope"}}, nil)
		if got.Code != want.Code || got.Tokens(t).Error != want.Tokens(t).Error || got.Code == http.StatusOK {
			t.Fatalf("revocation %d %q, token endpoint %d %q", got.Code, got.Body, want.Code, want.Body)
		}
		if refreshRevoked(t, e, tk.RefreshToken) {
			t.Error("revoked")
		}
	})
	t.Run("the right client secret revokes", func(t *testing.T) {
		e := server.New(t)
		conf := server.ClientConfidential
		tk := exchangeConfidential(t, e, conf)
		v := url.Values{"token": {tk.RefreshToken}, "client_id": {conf.ID}, "client_secret": {e.Secret(conf.ID)}}
		wantRevokeAnswer(t, revoke(t, e, v, nil))
		if !refreshRevoked(t, e, tk.RefreshToken) {
			t.Error("not revoked")
		}
	})
	t.Run("a disabled realm does not block revocation", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		e.Reload(t, func(y string) string { return strings.Replace(y, "name: main\n", "name: main\nenabled: false\n", 1) })
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, tk.RefreshToken), nil))
		if !refreshRevoked(t, e, tk.RefreshToken) {
			t.Error("not revoked")
		}
	})
	t.Run("a JSON body is refused", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		r := e.NewClient().Request(t, http.MethodPost, revokeURL, `{"token":"`+tk.RefreshToken+`"}`,
			http.Header{"Content-Type": {"application/json"}})
		wantError(t, r, 400, "invalid_request")
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("discovery lists the endpoint and its auth methods", func(t *testing.T) {
		e := server.New(t)
		r := e.NewClient().Request(t, http.MethodGet, server.Issuer+"/.well-known/openid-configuration", "", nil)
		var doc map[string]any
		if err := json.Unmarshal([]byte(r.Body), &doc); err != nil {
			t.Fatalf("discovery is not JSON: %v", err)
		}
		if doc["revocation_endpoint"] != revokeURL {
			t.Errorf("revocation_endpoint %v, want %s", doc["revocation_endpoint"], revokeURL)
		}
		methods, _ := json.Marshal(doc["revocation_endpoint_auth_methods_supported"])
		if got, want := string(methods), `["client_secret_basic","client_secret_post","none"]`; got != want {
			t.Errorf("revocation_endpoint_auth_methods_supported %s, want %s", got, want)
		}
	})
}

// Covers: FR-38, SEC-34
// Acceptance: Revocation endpoint
func TestRevocationLooksBeforeItWrites(t *testing.T) {
	app := server.ClientQuery
	// writes runs f and returns how many write transactions it started.
	writes := func(e *server.Env, f func()) int {
		before := e.Faults.Writes()
		f()
		return e.Faults.Writes() - before
	}
	wantNoWrite := func(t *testing.T, e *server.Env, v url.Values) {
		t.Helper()
		var r server.Response
		if n := writes(e, func() { r = revoke(t, e, v, nil) }); n != 0 {
			t.Errorf("%d write transactions, want 0", n)
		}
		wantRevokeAnswer(t, r)
	}
	wantOneWrite := func(t *testing.T, e *server.Env, v url.Values) {
		t.Helper()
		var r server.Response
		if n := writes(e, func() { r = revoke(t, e, v, nil) }); n != 1 {
			t.Errorf("%d write transactions, want 1", n)
		}
		wantRevokeAnswer(t, r)
	}
	t.Run("a made-up token", func(t *testing.T) {
		e := server.New(t)
		wantNoWrite(t, e, revokeForm(app, "nope"))
	})
	t.Run("another client's refresh token", func(t *testing.T) {
		e := server.New(t)
		fr := exchange(t, e, server.ClientFragment)
		wantNoWrite(t, e, revokeForm(app, fr.RefreshToken))
	})
	t.Run("an ID token", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		wantNoWrite(t, e, revokeForm(app, tk.IDToken))
	})
	t.Run("an expired access token", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		e.Clock.Advance(time.Hour)
		wantNoWrite(t, e, revokeForm(app, tk.AccessToken))
	})
	t.Run("a token of a revoked session", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		wantRevokeAnswer(t, revoke(t, e, revokeForm(app, tk.RefreshToken), nil))
		wantNoWrite(t, e, revokeForm(app, tk.RefreshToken))
	})
	t.Run("a live refresh token revokes its session with one write", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		wantOneWrite(t, e, revokeForm(app, tk.RefreshToken))
	})
	t.Run("an expired refresh token of a live session revokes it with one write", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		e.Clock.Advance(721 * time.Hour)
		wantOneWrite(t, e, revokeForm(app, tk.RefreshToken))
	})
	t.Run("a live access token revokes its session with one write", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		wantOneWrite(t, e, revokeForm(app, tk.AccessToken))
	})
}

// Covers: FR-38
// Acceptance: Revocation endpoint
func TestRevocationStoreFailures(t *testing.T) {
	app := server.ClientQuery
	rows := []struct {
		name   string
		op     string
		err    error
		status int
		code   string
	}{
		{"unavailable on the lookup", "Refresh.FindByHash", store.ErrUnavailable, 503, "temporarily_unavailable"},
		{"failing lookup", "Refresh.FindByHash", fmt.Errorf("disk on fire"), 500, "server_error"},
		{"unavailable on the session check", "Refresh.SessionLive", store.ErrUnavailable, 503, "temporarily_unavailable"},
		{"unavailable on the write", "Refresh.RevokeSession", store.ErrUnavailable, 503, "temporarily_unavailable"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			e := server.New(t)
			tk := exchange(t, e, app)
			e.Faults.Fail(row.op, row.err)
			wantError(t, revoke(t, e, revokeForm(app, tk.RefreshToken), nil), row.status, row.code)
			e.Faults.Fail(row.op, nil)
			if refreshRevoked(t, e, tk.RefreshToken) {
				t.Error("revoked despite the failure")
			}
		})
	}
}

// Covers: FR-38, FR-26 (part), SEC-18 (part)
// Acceptance: Revocation endpoint
func TestRevocationCORS(t *testing.T) {
	app := server.ClientQuery
	const own, other, stranger = "https://app.example.com", "https://frag.example.com", "https://evil.example.com"
	preflight := func(t *testing.T, e *server.Env, origin string) server.Response {
		return e.NewClient().Request(t, http.MethodOptions, revokeURL, "", http.Header{
			"Origin": {origin}, "Access-Control-Request-Method": {"POST"},
		})
	}
	withOrigin := func(origin string) http.Header { return http.Header{"Origin": {origin}} }

	t.Run("preflight from the client's origin and from another client's", func(t *testing.T) {
		e := server.New(t)
		for _, o := range []string{own, other} {
			r := preflight(t, e, o)
			if r.Code != http.StatusNoContent || r.Header.Get("Access-Control-Allow-Origin") != o ||
				r.Header.Get("Access-Control-Allow-Methods") != "POST, OPTIONS" ||
				r.Header.Get("Access-Control-Allow-Headers") != "Authorization, Content-Type" {
				t.Errorf("%s: %d %v", o, r.Code, r.Header)
			}
		}
		if r := preflight(t, e, stranger); r.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("an unregistered origin got CORS headers: %v", r.Header)
		}
	})
	t.Run("the POST from the client's origin", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		h := withOrigin(own)
		h.Set("Content-Type", "application/x-www-form-urlencoded")
		r := e.NewClient().Request(t, http.MethodPost, revokeURL, revokeForm(app, tk.RefreshToken).Encode(), h)
		wantRevokeAnswer(t, r)
		if r.Header.Get("Access-Control-Allow-Origin") != own || r.Header.Get("Vary") != "Origin" {
			t.Errorf("headers %v", r.Header)
		}
	})
	t.Run("the POST from an unregistered origin is refused and revokes nothing", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		h := withOrigin(stranger)
		h.Set("Content-Type", "application/x-www-form-urlencoded")
		r := e.NewClient().Request(t, http.MethodPost, revokeURL, revokeForm(app, tk.RefreshToken).Encode(), h)
		wantError(t, r, 400, "invalid_request")
		if r.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("headers %v", r.Header)
		}
		wantAlive(t, e, app, tk.RefreshToken)
	})
}

// Covers: FR-21 (part), FR-58 (part)
// Acceptance: Wrong method (part)
func TestRevocationWrongMethods(t *testing.T) {
	e := server.New(t)
	tk := exchange(t, e, server.ClientQuery)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		r := e.NewClient().Request(t, m, revokeURL+"?token="+url.QueryEscape(tk.RefreshToken), "", nil)
		if r.Code != http.StatusMethodNotAllowed || r.Header.Get("Allow") != "POST, OPTIONS" {
			t.Errorf("%s: %d allow %q", m, r.Code, r.Header.Get("Allow"))
		}
		if m != http.MethodHead && !strings.Contains(r.Body, `"error":"invalid_request"`) {
			t.Errorf("%s: body %q", m, r.Body)
		}
	}
	wantAlive(t, e, server.ClientQuery, tk.RefreshToken)
}

// Covers: FR-38
func TestRevocationUnroutedRequest(t *testing.T) {
	// Without routing information the answer is the server error.
	w := httptest.NewRecorder()
	oidc.NewRevoke(oidc.RevokeConfig{}).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/main/revoke", nil))
	if w.Code != 500 {
		t.Fatalf("status %d", w.Code)
	}
}

// Covers: FR-38
func TestRevocationRequestErrors(t *testing.T) {
	e := server.New(t)
	tk := exchange(t, e, server.ClientQuery)
	// A plain OPTIONS (not a preflight) is answered 204 and revokes nothing.
	if r := e.NewClient().Request(t, http.MethodOptions, revokeURL, "", nil); r.Code != http.StatusNoContent {
		t.Errorf("OPTIONS: status %d, want 204", r.Code)
	}
	// A body that is not a form is invalid_request.
	r := e.NewClient().Request(t, http.MethodPost, revokeURL, "token=%zz&client_id=web", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	wantError(t, r, 400, "invalid_request")
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", r.Header.Get("Cache-Control"))
	}
	wantAlive(t, e, server.ClientQuery, tk.RefreshToken)
}
