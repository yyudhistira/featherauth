package oidc_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	isrv "github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

func basic(id, secret string) http.Header {
	cred := url.QueryEscape(id) + ":" + url.QueryEscape(secret)
	return http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(cred))}}
}

// checkClients validates a realm with the given clients block the way
// `config check` does and returns the diagnostics for that realm file.
func checkClients(t *testing.T, clients string) []config.Diagnostic {
	t.Helper()
	l, d := testutil.NewConfigDir(t, testutil.ProvidersServerYAML, map[string]string{"main": testutil.MinimalRealm("main")})
	d.Secret(t, "secrets/other/client_secret")
	testutil.WriteRealm(t, d, "other", testutil.RealmYAML("other", clients))
	res := l.Reload(context.Background())
	var out []config.Diagnostic
	for _, dg := range res.Diagnostics {
		if dg.File == "realms/other.yaml" {
			out = append(out, dg)
		}
	}
	return out
}

const confidentialClient = "    type: confidential\n    client_secret_file: secrets/other/client_secret\n    redirect_uris: [https://app.example.com/callback]\n"

// post sends a form to the token endpoint from a new browser.
func post(t *testing.T, e *server.Env, form url.Values, h http.Header) server.Response {
	t.Helper()
	return e.NewClient().PostToken(t, form, h)
}

// wantError checks the status and the OAuth error of a token response.
func wantError(t *testing.T, r server.Response, status int, code string) {
	t.Helper()
	if r.Code != status {
		t.Fatalf("status %d, want %d (%s)", r.Code, status, r.Body)
	}
	if got := r.Tokens(t).Error; got != code {
		t.Fatalf("error %q, want %q (%s)", got, code, r.Body)
	}
}

// wantTokens checks a success and returns the tokens.
func wantTokens(t *testing.T, r server.Response) server.Tokens {
	t.Helper()
	if r.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (%s)", r.Code, r.Body)
	}
	tk := r.Tokens(t)
	if tk.AccessToken == "" || tk.IDToken == "" || tk.RefreshToken == "" || tk.TokenType != "Bearer" {
		t.Fatalf("tokens %+v", tk)
	}
	return tk
}

// exchange logs in as the app and exchanges the code, as a public client.
func exchange(t *testing.T, e *server.Env, app server.App, kv ...string) server.Tokens {
	t.Helper()
	return wantTokens(t, post(t, e, server.CodeForm(app, e.Login(t, app, kv...)), nil))
}

// exchangeConfidential is exchange for a confidential client, with its secret
// in the body.
func exchangeConfidential(t *testing.T, e *server.Env, app server.App) server.Tokens {
	t.Helper()
	f := server.CodeForm(app, e.Login(t, app))
	f.Set("client_secret", e.Secret(app.ID))
	return wantTokens(t, post(t, e, f, nil))
}

// Covers: FR-07 (part)
// Acceptance: Confidential client
func TestTokenClientAuthentication(t *testing.T) {
	app := server.ClientConfidential
	tests := []struct {
		name   string
		secret func(e *server.Env) (extra url.Values, h http.Header)
		status int
		code   string
		basic  bool // WWW-Authenticate: Basic expected
	}{
		{"basic, right secret", func(e *server.Env) (url.Values, http.Header) { return nil, basic("srv", e.Secret("srv")) }, 200, "", false},
		{"post, right secret", func(e *server.Env) (url.Values, http.Header) {
			return url.Values{"client_secret": {e.Secret("srv")}}, nil
		}, 200, "", false},
		{"basic, wrong secret", func(*server.Env) (url.Values, http.Header) { return nil, basic("srv", "wrong") }, 401, "invalid_client", true},
		{"basic, no secret", func(*server.Env) (url.Values, http.Header) { return nil, basic("srv", "") }, 401, "invalid_client", true},
		{"post, wrong secret", func(*server.Env) (url.Values, http.Header) {
			return url.Values{"client_secret": {"wrong"}}, nil
		}, 400, "invalid_client", false},
		{"post, no secret", func(*server.Env) (url.Values, http.Header) { return nil, nil }, 400, "invalid_client", false},
		{"post, empty secret", func(*server.Env) (url.Values, http.Header) {
			return url.Values{"client_secret": {""}}, nil
		}, 400, "invalid_client", false},
		{"both methods", func(e *server.Env) (url.Values, http.Header) {
			return url.Values{"client_secret": {e.Secret("srv")}}, basic("srv", e.Secret("srv"))
		}, 400, "invalid_request", false},
		{"basic for another client than the body", func(e *server.Env) (url.Values, http.Header) {
			return nil, basic("fixed", e.Secret("fixed"))
		}, 400, "invalid_request", false},
		{"malformed Basic header", func(*server.Env) (url.Values, http.Header) {
			return nil, http.Header{"Authorization": {"Basic !!"}}
		}, 401, "invalid_client", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := server.New(t)
			form := server.CodeForm(app, e.Login(t, app))
			extra, h := tt.secret(e)
			for k, v := range extra {
				form[k] = v
			}
			r := post(t, e, form, h)
			if tt.status == 200 {
				wantTokens(t, r)
				return
			}
			wantError(t, r, tt.status, tt.code)
			if got := strings.HasPrefix(r.Header.Get("WWW-Authenticate"), "Basic"); got != tt.basic {
				t.Errorf("WWW-Authenticate %q, want Basic: %v", r.Header.Get("WWW-Authenticate"), tt.basic)
			}
		})
	}
	t.Run("a refused client does not use up the code", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, app)
		wantError(t, post(t, e, server.CodeForm(app, res), basic("srv", "wrong")), 401, "invalid_client")
		wantTokens(t, post(t, e, server.CodeForm(app, res), basic("srv", e.Secret("srv"))))
	})
	t.Run("an unknown client and a missing client_id", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, app)
		wantError(t, post(t, e, server.CodeForm(app, res, "client_id", "nobody"), nil), 400, "invalid_client")
		wantError(t, post(t, e, server.CodeForm(app, res, "client_id", "-"), nil), 400, "invalid_client")
	})
	t.Run("a public client sending a secret, and an empty one", func(t *testing.T) {
		e := server.New(t)
		pub := server.ClientQuery
		res := e.Login(t, pub)
		f := server.CodeForm(pub, res, "client_secret", "anything")
		wantError(t, post(t, e, f, nil), 400, "invalid_client")
		wantError(t, post(t, e, server.CodeForm(pub, res), basic("web", "anything")), 401, "invalid_client")
		f = server.CodeForm(pub, res, "client_secret", "")
		wantTokens(t, post(t, e, f, nil)) // the empty secret counts as absent
	})
	t.Run("a client_id or client_secret sent twice", func(t *testing.T) {
		e := server.New(t)
		f := server.CodeForm(app, e.Login(t, app))
		f.Add("client_id", "web")
		wantError(t, post(t, e, f, nil), 400, "invalid_request")
	})
}

// Covers: FR-07 (part)
// Acceptance: Token endpoint headers
func TestTokenEndpointHeaders(t *testing.T) {
	noStore := func(t *testing.T, r server.Response) {
		t.Helper()
		if got := r.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control %q", got)
		}
		if got := r.Header.Get("Pragma"); got != "no-cache" {
			t.Errorf("Pragma %q", got)
		}
	}
	e := server.New(t)
	app := server.ClientQuery
	res := e.Login(t, app)

	t.Run("an error response", func(t *testing.T) {
		r := post(t, e, server.CodeForm(app, res, "code_verifier", "short"), nil)
		wantError(t, r, 400, "invalid_request")
		noStore(t, r)
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type %q", r.Header.Get("Content-Type"))
		}
	})
	t.Run("a JSON request body", func(t *testing.T) {
		body := `{"grant_type":"authorization_code","client_id":"web","code":"x"}`
		r := e.NewClient().Request(t, http.MethodPost, server.Issuer+"/token", body, http.Header{"Content-Type": {"application/json"}})
		wantError(t, r, 400, "invalid_request")
		noStore(t, r)
	})
	t.Run("no content type", func(t *testing.T) {
		r := e.NewClient().Request(t, http.MethodPost, server.Issuer+"/token", "grant_type=refresh_token", nil)
		wantError(t, r, 400, "invalid_request")
	})
	t.Run("a success response", func(t *testing.T) {
		r := post(t, e, server.CodeForm(app, res), nil)
		wantTokens(t, r)
		noStore(t, r)
		if tk := r.Tokens(t); tk.ExpiresIn != 900 || tk.Scope == "" {
			t.Errorf("tokens %+v", tk)
		}
	})
	t.Run("the store unavailable", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, app)
		e.Faults.FailWrite = fmt.Errorf("%w: database is locked", store.ErrUnavailable)
		r := post(t, e, server.CodeForm(app, res), nil)
		wantError(t, r, 503, "temporarily_unavailable")
		noStore(t, r)
		r = post(t, e, server.RefreshForm(app, "whatever"), nil)
		wantError(t, r, 503, "temporarily_unavailable")
	})
	t.Run("another store failure is a 500", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, app)
		e.Faults.FailWrite = fmt.Errorf("disk on fire")
		wantError(t, post(t, e, server.CodeForm(app, res), nil), 500, "server_error")
	})
}

// Covers: FR-07 (part)
func TestTokenRequestShape(t *testing.T) {
	app := server.ClientQuery
	t.Run("grant types", func(t *testing.T) {
		e := server.New(t)
		for _, g := range []string{"password", "client_credentials", "", "AUTHORIZATION_CODE"} {
			r := post(t, e, url.Values{"grant_type": {g}, "client_id": {app.ID}}, nil)
			wantError(t, r, 400, "unsupported_grant_type")
		}
		wantError(t, post(t, e, url.Values{"client_id": {app.ID}}, nil), 400, "unsupported_grant_type")
	})
	t.Run("the client is authenticated before the grant is looked at", func(t *testing.T) {
		e := server.New(t)
		wantError(t, post(t, e, url.Values{"grant_type": {"password"}, "client_id": {"nobody"}}, nil), 400, "invalid_client")
	})
	t.Run("a scope parameter is ignored", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, app)
		tk := wantTokens(t, post(t, e, server.CodeForm(app, res, "scope", "nonsense admin"), nil))
		rf := wantTokens(t, post(t, e, server.RefreshForm(app, tk.RefreshToken, "scope", "other"), nil))
		if rf.Scope != tk.Scope {
			t.Errorf("scope %q after refresh, %q before", rf.Scope, tk.Scope)
		}
	})
	t.Run("the code in the URL query is not read", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, app)
		f := server.CodeForm(app, res)
		q := url.Values{"code": {f.Get("code")}}
		f.Del("code")
		r := e.NewClient().Request(t, http.MethodPost, server.Issuer+"/token?"+q.Encode(), f.Encode(),
			http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		wantError(t, r, 400, "invalid_grant")
	})
	t.Run("methods", func(t *testing.T) {
		e := server.New(t)
		for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			r := e.NewClient().Request(t, m, server.Issuer+"/token", "", nil)
			wantError(t, r, 405, "invalid_request")
			if r.Header.Get("Allow") != "POST, OPTIONS" {
				t.Errorf("%s: Allow %q", m, r.Header.Get("Allow"))
			}
		}
	})
	t.Run("a request body over 64 KB", func(t *testing.T) {
		e := server.New(t)
		body := "grant_type=refresh_token&refresh_token=" + strings.Repeat("a", 70<<10)
		r := e.NewClient().Request(t, http.MethodPost, server.Issuer+"/token", body,
			http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		wantError(t, r, 413, "invalid_request")
	})
	t.Run("a code grant without a code or a refresh grant without a token", func(t *testing.T) {
		e := server.New(t)
		wantError(t, post(t, e, server.CodeForm(app, server.Result{}), nil), 400, "invalid_grant")
		wantError(t, post(t, e, server.RefreshForm(app, ""), nil), 400, "invalid_grant")
	})
}

// Covers: FR-07 (part), SEC-01 (part)
// Acceptance: PKCE
func TestTokenPKCE(t *testing.T) {
	app := server.ClientQuery
	e := server.New(t)
	wrong := strings.Repeat("a", 43)
	wantError(t, post(t, e, server.CodeForm(app, e.Login(t, app), "code_verifier", wrong), nil), 400, "invalid_grant")
	wantError(t, post(t, e, server.CodeForm(app, e.Login(t, app), "code_verifier", strings.Repeat("a", 42)), nil), 400, "invalid_request")
	wantError(t, post(t, e, server.CodeForm(app, e.Login(t, app), "code_verifier", "-"), nil), 400, "invalid_grant")
	wantError(t, post(t, e, server.CodeForm(app, e.Login(t, app), "code_verifier", strings.Repeat("a", 129)), nil), 400, "invalid_request")
	wantError(t, post(t, e, server.CodeForm(app, e.Login(t, app), "code_verifier", strings.Repeat("a", 42)+"!"), nil), 400, "invalid_request")
	t.Run("a malformed verifier does not use up the code", func(t *testing.T) {
		res := e.Login(t, app)
		wantError(t, post(t, e, server.CodeForm(app, res, "code_verifier", "short"), nil), 400, "invalid_request")
		wantTokens(t, post(t, e, server.CodeForm(app, res), nil))
	})
	t.Run("a wrong verifier uses up the code", func(t *testing.T) {
		res := e.Login(t, app)
		wantError(t, post(t, e, server.CodeForm(app, res, "code_verifier", wrong), nil), 400, "invalid_grant")
		wantError(t, post(t, e, server.CodeForm(app, res), nil), 400, "invalid_grant")
	})
}

// Covers: FR-07 (part), SEC-01 (part), FR-32 (part)
// Acceptance: PKCE downgrade
func TestTokenPKCEDowngrade(t *testing.T) {
	t.Run("config check warns for each client and names RFC 9700 for the public one", func(t *testing.T) {
		pub := checkClients(t, "clients:\n  app:\n    require_pkce: false\n    refresh_idle_lifetime: 24h\n    session_max_lifetime: 720h\n    redirect_uris: [https://app.example.com/callback]\n")
		if len(pub) != 1 || pub[0].Severity != config.Warning || !strings.HasSuffix(pub[0].Field, "require_pkce") || !strings.Contains(pub[0].Message, "RFC 9700 section 2.1.1") {
			t.Errorf("public client: %v", pub)
		}
		con := checkClients(t, "clients:\n  app:\n"+confidentialClient+"    require_pkce: false\n")
		if len(con) != 1 || con[0].Severity != config.Warning || !strings.HasSuffix(con[0].Field, "require_pkce") {
			t.Errorf("confidential client: %v", con)
		}
	})
	app := server.ClientLegacy
	e := server.New(t)
	t.Run("a code without a challenge and a verifier", func(t *testing.T) {
		res := e.Login(t, app, "code_challenge", "-", "code_challenge_method", "-")
		wantError(t, post(t, e, server.CodeForm(app, res), nil), 400, "invalid_grant")
	})
	t.Run("a code without a challenge and no verifier", func(t *testing.T) {
		res := e.Login(t, app, "code_challenge", "-", "code_challenge_method", "-")
		wantTokens(t, post(t, e, server.CodeForm(app, res, "code_verifier", "-"), nil))
	})
	t.Run("a code with a challenge needs the verifier", func(t *testing.T) {
		res := e.Login(t, app)
		wantError(t, post(t, e, server.CodeForm(app, res, "code_verifier", "-"), nil), 400, "invalid_grant")
	})
}

// Covers: FR-07 (part), SEC-06 (part)
// Acceptance: Code lifetime and reuse
func TestTokenCodeLifetimeAndReuse(t *testing.T) {
	app := server.ClientQuery
	t.Run("reuse revokes the session", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, app)
		tk := wantTokens(t, post(t, e, server.CodeForm(app, res), nil))
		wantError(t, post(t, e, server.CodeForm(app, res), nil), 400, "invalid_grant")
		wantError(t, post(t, e, server.RefreshForm(app, tk.RefreshToken), nil), 400, "invalid_grant")
	})
	for _, tt := range []struct {
		name    string
		opts    []server.Option
		life    time.Duration
		advance time.Duration
	}{
		{"default lifetime", nil, 60 * time.Second, 0},
		{"a non-default lifetime", []server.Option{server.WithTokenSetting("code_lifetime: 5m")}, 5 * time.Minute, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := server.New(t, tt.opts...)
			inside := e.Login(t, app)
			e.Clock.Advance(tt.life - time.Second)
			wantTokens(t, post(t, e, server.CodeForm(app, inside), nil))
			late := e.Login(t, app)
			e.Clock.Advance(tt.life)
			wantError(t, post(t, e, server.CodeForm(app, late), nil), 400, "invalid_grant")
		})
	}
}

// Covers: FR-07 (part)
// Acceptance: Code binding
func TestTokenCodeBinding(t *testing.T) {
	t.Run("another client", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, server.ClientQuery)
		wantError(t, post(t, e, server.CodeForm(server.ClientLegacy, res), nil), 400, "invalid_grant")
	})
	t.Run("another redirect URI", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, server.ClientQuery)
		wantError(t, post(t, e, server.CodeForm(server.ClientQuery, res, "redirect_uri", "https://evil.example.com/callback"), nil), 400, "invalid_grant")
	})
	t.Run("a user disabled after the code was issued", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, server.ClientQuery)
		e.SetDisabled(t, true)
		wantError(t, post(t, e, server.CodeForm(server.ClientQuery, res), nil), 400, "invalid_grant")
	})
}

// refresh sends a refresh grant of the public client.
func refresh(t *testing.T, e *server.Env, app server.App, rt string) server.Response {
	t.Helper()
	return post(t, e, server.RefreshForm(app, rt), nil)
}

// Covers: FR-08 (part), SEC-06 (part)
// Acceptance: Refresh rotation
func TestTokenRefreshRotation(t *testing.T) {
	app := server.ClientQuery
	e := server.New(t)
	first := exchange(t, e, app)
	second := wantTokens(t, refresh(t, e, app, first.RefreshToken))
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("the refresh token was not rotated")
	}
	e.Clock.Advance(31 * time.Second) // past refresh_reuse_grace
	wantError(t, refresh(t, e, app, first.RefreshToken), 400, "invalid_grant")
	wantError(t, refresh(t, e, app, second.RefreshToken), 400, "invalid_grant") // the session is revoked
}

// Covers: FR-08 (part)
// Acceptance: Refresh within grace
func TestTokenRefreshWithinGrace(t *testing.T) {
	app := server.ClientQuery
	t.Run("two refreshes at once", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		var wg sync.WaitGroup
		codes := make([]int, 2)
		for i := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[i] = e.NewClient().PostToken(t, server.RefreshForm(app, tk.RefreshToken), nil).Code
			}()
		}
		wg.Wait()
		if codes[0] != 200 || codes[1] != 200 {
			t.Errorf("statuses %v", codes)
		}
	})
	// three presentations inside the window, then a use of one successor
	setup := func(t *testing.T) (e *server.Env, old string, succ []string) {
		e = server.New(t)
		old = exchange(t, e, app).RefreshToken
		for range 3 {
			e.Clock.Advance(time.Second)
			succ = append(succ, wantTokens(t, refresh(t, e, app, old)).RefreshToken)
		}
		if succ[0] == succ[1] || succ[1] == succ[2] {
			t.Fatalf("the successors are not fresh: %v", succ)
		}
		return e, old, succ
	}
	t.Run("another successor after one was used revokes the session", func(t *testing.T) {
		e, _, succ := setup(t)
		used := wantTokens(t, refresh(t, e, app, succ[0]))
		wantError(t, refresh(t, e, app, succ[1]), 400, "invalid_grant")
		wantError(t, refresh(t, e, app, used.RefreshToken), 400, "invalid_grant") // revoked even inside the window
	})
	t.Run("the old token after a successor was used revokes the session", func(t *testing.T) {
		e, old, succ := setup(t)
		used := wantTokens(t, refresh(t, e, app, succ[2]))
		wantError(t, refresh(t, e, app, old), 400, "invalid_grant")
		wantError(t, refresh(t, e, app, used.RefreshToken), 400, "invalid_grant")
	})
	t.Run("the used successor is the only active token", func(t *testing.T) {
		e, _, succ := setup(t)
		used := wantTokens(t, refresh(t, e, app, succ[1]))
		wantTokens(t, refresh(t, e, app, used.RefreshToken))
	})
}

// Covers: FR-08 (part), SEC-06 (part)
// Acceptance: Refresh binding
func TestTokenRefreshBinding(t *testing.T) {
	t.Run("another client", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, server.ClientQuery)
		wantError(t, refresh(t, e, server.ClientLegacy, tk.RefreshToken), 400, "invalid_grant")
		wantTokens(t, refresh(t, e, server.ClientQuery, tk.RefreshToken)) // the token is left alone
	})
	t.Run("a confidential client without its secret", func(t *testing.T) {
		e := server.New(t)
		tk := exchangeConfidential(t, e, server.ClientConfidential)
		wantError(t, refresh(t, e, server.ClientConfidential, tk.RefreshToken), 400, "invalid_client")
		f := server.RefreshForm(server.ClientConfidential, tk.RefreshToken, "client_secret", e.Secret("srv"))
		wantTokens(t, post(t, e, f, nil))
	})
	t.Run("the client is removed from the realm file", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, server.ClientQuery)
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n    web_origins: [https://app.example.com]\n", "", 1)
		})
		// another client presenting the token, and the removed client itself
		wantError(t, refresh(t, e, server.ClientLegacy, tk.RefreshToken), 400, "invalid_grant")
		wantError(t, refresh(t, e, server.ClientQuery, tk.RefreshToken), 400, "invalid_client")
	})
}

// Covers: FR-08 (part), FR-32 (part)
// Acceptance: Rotation off
func TestTokenRotationOff(t *testing.T) {
	t.Run("config check rejects a public client and accepts a confidential one", func(t *testing.T) {
		pub := checkClients(t, "clients:\n  app:\n    refresh_token_rotation: false\n    redirect_uris: [https://app.example.com/callback]\n")
		if len(pub) != 1 || pub[0].Severity != config.Error || !strings.HasSuffix(pub[0].Field, "refresh_token_rotation") {
			t.Errorf("public client: %v", pub)
		}
		if con := checkClients(t, "clients:\n  app:\n"+confidentialClient+"    refresh_token_rotation: false\n"); len(con) != 0 {
			t.Errorf("confidential client: %v", con)
		}
	})
	app := server.ClientFixed
	e := server.New(t)
	tk := exchangeConfidential(t, e, app)
	form := func() url.Values {
		return server.RefreshForm(app, tk.RefreshToken, "client_secret", e.Secret("fixed"))
	}
	e.Clock.Advance(100 * time.Hour)
	again := wantTokens(t, post(t, e, form(), nil))
	if again.RefreshToken != tk.RefreshToken {
		t.Fatal("a client with rotation off got another refresh token")
	}
	if again.RefreshExpiresIn != 720*3600 { // 720h from this use, not from the login
		t.Errorf("refresh_expires_in %d", again.RefreshExpiresIn)
	}
	e.Clock.Advance(time.Hour)
	wantTokens(t, post(t, e, form(), nil)) // keeps working
	e.Clock.Advance(40 * time.Second)
	wantTokens(t, post(t, e, form(), nil)) // also past the reuse grace
}

// Covers: FR-08 (part)
// Acceptance: Long-lived session
func TestTokenLongLivedSession(t *testing.T) {
	t.Run("a client with a long idle lifetime", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, server.ClientLong)
		e.Clock.Advance(400 * 24 * time.Hour)
		again := wantTokens(t, refresh(t, e, server.ClientLong, tk.RefreshToken))
		if again.RefreshExpiresIn != 17520*3600 {
			t.Errorf("refresh_expires_in %d", again.RefreshExpiresIn)
		}
	})
	t.Run("a client with the short default is refused", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, server.ClientQuery)
		e.Clock.Advance(400 * 24 * time.Hour)
		wantError(t, refresh(t, e, server.ClientQuery, tk.RefreshToken), 400, "invalid_grant")
	})
}

// Covers: FR-08 (part)
// Acceptance: Sliding expiry
func TestTokenSlidingExpiry(t *testing.T) {
	t.Run("near the session limit", func(t *testing.T) {
		e := server.New(t)
		app := server.ClientCapped
		tk := exchange(t, e, app)
		if tk.RefreshExpiresIn != 2*3600 {
			t.Errorf("refresh_expires_in %d at login", tk.RefreshExpiresIn)
		}
		e.Clock.Advance(110 * time.Minute)
		near := wantTokens(t, refresh(t, e, app, tk.RefreshToken))
		if near.RefreshExpiresIn != 10*60 { // never past session_started_at + 2h
			t.Errorf("refresh_expires_in %d", near.RefreshExpiresIn)
		}
		e.Clock.Advance(11 * time.Minute)
		wantError(t, refresh(t, e, app, near.RefreshToken), 400, "invalid_grant")
	})
	t.Run("without a session limit only the idle lifetime applies", func(t *testing.T) {
		e := server.New(t)
		app := server.ClientLong
		tk := exchange(t, e, app)
		e.Clock.Advance(1000 * time.Hour)
		again := wantTokens(t, refresh(t, e, app, tk.RefreshToken))
		if again.RefreshExpiresIn != 17520*3600 {
			t.Errorf("refresh_expires_in %d", again.RefreshExpiresIn)
		}
	})
}

// Covers: FR-26 (part), SEC-18 (part)
// Acceptance: CORS (part)
func TestTokenCORS(t *testing.T) {
	app := server.ClientQuery
	const own, other, stranger = "https://app.example.com", "https://frag.example.com", "https://evil.example.com"
	preflight := func(t *testing.T, e *server.Env, origin string) server.Response {
		return e.NewClient().Request(t, http.MethodOptions, server.Issuer+"/token", "", http.Header{
			"Origin": {origin}, "Access-Control-Request-Method": {"POST"},
		})
	}
	withOrigin := func(origin string) http.Header { return http.Header{"Origin": {origin}} }

	t.Run("preflight from the client's origin and from another client's", func(t *testing.T) {
		e := server.New(t)
		for _, o := range []string{own, other} {
			r := preflight(t, e, o)
			if r.Code != 204 || r.Header.Get("Access-Control-Allow-Origin") != o ||
				r.Header.Get("Access-Control-Allow-Methods") != "POST, OPTIONS" ||
				r.Header.Get("Access-Control-Allow-Headers") != "Authorization, Content-Type, DPoP" {
				t.Errorf("%s: %d %v", o, r.Code, r.Header)
			}
		}
		if r := preflight(t, e, stranger); r.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("an unregistered origin got CORS headers: %v", r.Header)
		}
	})
	t.Run("the POST from the client's origin", func(t *testing.T) {
		e := server.New(t)
		r := post(t, e, server.CodeForm(app, e.Login(t, app)), withOrigin(own))
		wantTokens(t, r)
		if r.Header.Get("Access-Control-Allow-Origin") != own || r.Header.Get("Vary") != "Origin" {
			t.Errorf("headers %v", r.Header)
		}
	})
	t.Run("the POST from another client's origin is refused for this client", func(t *testing.T) {
		e := server.New(t)
		res := e.Login(t, app)
		r := post(t, e, server.CodeForm(app, res), withOrigin(other))
		wantError(t, r, 400, "invalid_request")
		if r.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("headers %v", r.Header)
		}
		wantTokens(t, post(t, e, server.CodeForm(app, res), withOrigin(own))) // the code was not used
	})
	t.Run("the POST from an unregistered origin and without an origin", func(t *testing.T) {
		e := server.New(t)
		wantError(t, post(t, e, server.CodeForm(app, e.Login(t, app)), withOrigin(stranger)), 400, "invalid_request")
		wantTokens(t, post(t, e, server.CodeForm(app, e.Login(t, app)), nil))
	})
	t.Run("a client with no web origins refuses every origin", func(t *testing.T) {
		e := server.New(t)
		a := server.ClientLegacy
		wantError(t, post(t, e, server.CodeForm(a, e.Login(t, a)), withOrigin(own)), 400, "invalid_request")
	})
}

// A form body of 64 KB plus one byte is refused with 413 through the whole
// service: the OAuth error JSON at the token endpoint and an HTML error page
// at the authorize endpoint. The servers the service starts are all made by
// NewHTTPServer (internal/server, TestEveryHTTPServerIsBuiltByNewHTTPServer),
// whose timeouts this test reads.
//
// Covers: SEC-45
// Acceptance: Request size and slow clients
func TestFormBodyOfOver64KBIsRefused(t *testing.T) {
	e := server.New(t)
	form := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	pad := func(prefix string) string { return prefix + strings.Repeat("a", 64<<10+1-len(prefix)) }

	r := e.NewClient().Request(t, http.MethodPost, server.Issuer+"/token", pad("grant_type=refresh_token&refresh_token="), form)
	wantError(t, r, http.StatusRequestEntityTooLarge, "invalid_request")
	if got := r.Tokens(t).Description; got != "request body too large" {
		t.Errorf("token endpoint description %q, want request body too large", got)
	}

	r = e.NewClient().Request(t, http.MethodPost, server.Issuer+"/authorize", pad("client_id=web&state="), form)
	if r.Code != http.StatusRequestEntityTooLarge || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("authorize: status %d, type %q, want 413 and an HTML page", r.Code, r.Header.Get("Content-Type"))
	}
	if strings.HasPrefix(strings.TrimSpace(r.Body), "{") {
		t.Errorf("authorize answered JSON: %s", r.Body)
	}

	srv := isrv.NewHTTPServer(":0", http.NotFoundHandler())
	if srv.ReadHeaderTimeout != 5*time.Second || srv.ReadTimeout != 10*time.Second || srv.WriteTimeout != 60*time.Second || srv.IdleTimeout != 120*time.Second {
		t.Errorf("timeouts: header %v read %v write %v idle %v, want 5s, 10s, 60s, 120s", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}
