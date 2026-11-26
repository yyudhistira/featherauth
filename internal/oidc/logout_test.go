package oidc_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/token"
)

const (
	logoutURL = server.Issuer + "/logout"
	bye       = "https://app.example.com/bye"
	byeQuery  = "https://app.example.com/bye?from=app"
)

// logoutEnv starts the service with two return URLs registered for the "web"
// client.
func logoutEnv(t *testing.T, opts ...server.Option) *server.Env {
	t.Helper()
	e := server.New(t, opts...)
	e.Reload(t, func(y string) string {
		return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n",
			"  web:\n    redirect_uris: [https://app.example.com/callback]\n    post_logout_redirect_uris: ["+bye+", \""+byeQuery+"\"]\n", 1)
	})
	return e
}

func logout(t *testing.T, e *server.Env, method string, v url.Values, h http.Header) server.Response {
	t.Helper()
	c := e.NewClient()
	if method == http.MethodGet {
		return c.Request(t, method, logoutURL+"?"+v.Encode(), "", h)
	}
	hh := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	for k, x := range h {
		hh[k] = x
	}
	return c.Request(t, method, logoutURL, v.Encode(), hh)
}

// wantRevoked checks that the refresh token no longer works; wantAlive that it
// still does (and uses it up, so call it last).
func wantRevoked(t *testing.T, e *server.Env, app server.App, rt string) {
	t.Helper()
	wantError(t, refresh(t, e, app, rt), 400, "invalid_grant")
}

func wantAlive(t *testing.T, e *server.Env, app server.App, rt string) {
	t.Helper()
	wantTokens(t, refresh(t, e, app, rt))
}

func wantRedirect(t *testing.T, r server.Response, location string) {
	t.Helper()
	if r.Code != http.StatusFound || r.Header.Get("Location") != location {
		t.Fatalf("status %d location %q, want 302 %q (%s)", r.Code, r.Header.Get("Location"), location, r.Body)
	}
}

// wantRefusal checks the error page: no redirect, no revocation.
func wantRefusal(t *testing.T, r server.Response) {
	t.Helper()
	if r.Code != http.StatusBadRequest || r.Header.Get("Location") != "" ||
		!strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") || !strings.Contains(r.Body, "could not be verified") {
		t.Fatalf("status %d headers %v body %q, want the 400 error page", r.Code, r.Header, r.Body)
	}
}

func wantSignedOut(t *testing.T, r server.Response) {
	t.Helper()
	if r.Code != http.StatusOK || r.Header.Get("Location") != "" || !strings.Contains(r.Body, "You are signed out") ||
		!strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("status %d headers %v body %q, want the signed-out page", r.Code, r.Header, r.Body)
	}
}

// sidOf reads the sid claim of a token.
func sidOf(t *testing.T, jwt string) string {
	t.Helper()
	parts := strings.Split(jwt, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m["sid"].(string)
}

// foreignHint is an ID token for the "web" client of a realm of this name,
// with its own signing key, as a service on the same host would issue it; its
// sid is sid.
func foreignHint(t *testing.T, e *server.Env, realm, sid string) string {
	t.Helper()
	_, id := foreignTokens(t, e, realm, sid)
	return id
}

// foreignTokens is the access token and the ID token of foreignHint.
func foreignTokens(t *testing.T, e *server.Env, realm, sid string) (access, id string) {
	t.Helper()
	d := configdir.New(t)
	d.Server(t, "public_url: https://auth.example.com\n")
	d.Realm(t, realm, "name: "+realm+"\nkeys:\n  - { kid: main-1, file: secrets/k.pem, state: active }\n"+
		"providers:\n  google:\n    enabled: true\n    client_id: 1234.apps.googleusercontent.com\n    client_secret_file: secrets/google_secret\n"+
		"clients:\n  web:\n    redirect_uris: [https://app.example.com/callback]\n")
	d.Write(t, "secrets/k.pem", string(testutil.RSAKeyPEM(t))) // a key of its own, not the shared fixture
	d.Secret(t, "secrets/google_secret")
	l, err := config.NewLoader(d.Root, e.Clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	snap := l.Current()
	r, _ := snap.Realm(config.RealmName(realm))
	iss := token.NewIssuer(e.Clock, secure.Default, snap.Secrets())
	sub := token.Subject{ID: "u1", Email: "ann@example.com", EmailVerified: true, Name: "Ann"}
	ss := token.Session{ID: token.SessionID(sid), StartedAt: e.Clock.Now(), AuthTime: e.Clock.Now()}
	access, _, err = iss.Access(r, r.Clients["web"], sub, ss)
	if err != nil {
		t.Fatal(err)
	}
	id, err = iss.ID(r, r.Clients["web"], sub, ss, access)
	if err != nil {
		t.Fatal(err)
	}
	return access, id
}

// Covers: FR-11 (part)
// Acceptance: Logout by hint
func TestLogoutByHint(t *testing.T) {
	app := server.ClientQuery
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, row := range []struct {
			name    string
			advance time.Duration
			url     string
			state   string
			want    string
		}{
			{"valid hint", 0, bye, "st-9", bye + "?state=st-9"},
			{"expired hint", 2 * time.Hour, bye, "st-9", bye + "?state=st-9"},
			{"state is encoded", 0, bye, "a b&c=d", bye + "?state=a+b%26c%3Dd"},
			{"no state", 0, bye, "", bye},
			{"url with a query", 0, byeQuery, "st-9", byeQuery + "&state=st-9"},
		} {
			t.Run(method+" "+row.name, func(t *testing.T) {
				e := logoutEnv(t)
				tk := exchange(t, e, app)
				e.Clock.Advance(row.advance)
				v := url.Values{"id_token_hint": {tk.IDToken}, "client_id": {app.ID}, "post_logout_redirect_uri": {row.url}}
				if row.state != "" {
					v.Set("state", row.state)
				}
				wantRedirect(t, logout(t, e, method, v, nil), row.want)
				wantRevoked(t, e, app, tk.RefreshToken)
			})
		}
		t.Run(method+" hint without client_id or return URL", func(t *testing.T) {
			e := logoutEnv(t)
			tk := exchange(t, e, app)
			other := exchange(t, e, app) // another session of the user stays
			wantSignedOut(t, logout(t, e, method, url.Values{"id_token_hint": {tk.IDToken}}, nil))
			wantRevoked(t, e, app, tk.RefreshToken)
			wantAlive(t, e, app, other.RefreshToken)
		})
		t.Run(method+" hint and return URL without client_id", func(t *testing.T) {
			e := logoutEnv(t)
			tk := exchange(t, e, app)
			wantRedirect(t, logout(t, e, method, url.Values{"id_token_hint": {tk.IDToken}, "post_logout_redirect_uri": {bye}}, nil), bye)
			wantRevoked(t, e, app, tk.RefreshToken)
		})
	}
	t.Run("the default return URLs are the redirect URIs", func(t *testing.T) {
		e := server.New(t)
		tk := exchange(t, e, app)
		v := url.Values{"id_token_hint": {tk.IDToken}, "post_logout_redirect_uri": {app.RedirectURI}}
		wantRedirect(t, logout(t, e, http.MethodGet, v, nil), app.RedirectURI)
		wantRevoked(t, e, app, tk.RefreshToken)
	})
	t.Run("the whole session ends, the other clients' sessions stay", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		refreshed := wantTokens(t, refresh(t, e, app, tk.RefreshToken)) // a successor of the same session
		frag := exchange(t, e, server.ClientFragment)
		logout(t, e, http.MethodGet, url.Values{"id_token_hint": {tk.IDToken}}, nil)
		wantRevoked(t, e, app, refreshed.RefreshToken)
		wantAlive(t, e, server.ClientFragment, frag.RefreshToken)
	})
	t.Run("a hint of a removed client still ends its session when no URL is asked", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n    post_logout_redirect_uris: ["+bye+", \""+byeQuery+"\"]\n    web_origins: [https://app.example.com]\n", "", 1)
		})
		if _, ok := e.Realm.Clients["web"]; ok {
			t.Fatal("client not removed")
		}
		wantSignedOut(t, logout(t, e, http.MethodGet, url.Values{"id_token_hint": {tk.IDToken}}, nil))
	})
}

// Covers: FR-11 (part)
// Acceptance: Logout refusals
func TestLogoutRefusals(t *testing.T) {
	app := server.ClientQuery
	rows := []struct {
		name string
		v    func(e *server.Env, tk server.Tokens) url.Values
	}{
		{"bad signature", func(e *server.Env, tk server.Tokens) url.Values {
			return url.Values{"id_token_hint": {foreignHint(t, e, "main", sidOf(t, tk.IDToken))}, "post_logout_redirect_uri": {bye}}
		}},
		{"another realm", func(e *server.Env, tk server.Tokens) url.Values {
			return url.Values{"id_token_hint": {foreignHint(t, e, "other", sidOf(t, tk.IDToken))}, "post_logout_redirect_uri": {bye}}
		}},
		{"an access token as the hint", func(e *server.Env, tk server.Tokens) url.Values {
			return url.Values{"id_token_hint": {tk.AccessToken}, "post_logout_redirect_uri": {bye}}
		}},
		{"a refresh token as the hint", func(e *server.Env, tk server.Tokens) url.Values {
			return url.Values{"id_token_hint": {tk.RefreshToken}}
		}},
		{"garbage", func(e *server.Env, tk server.Tokens) url.Values {
			return url.Values{"id_token_hint": {"garbage"}}
		}},
		{"client_id of another client", func(e *server.Env, tk server.Tokens) url.Values {
			return url.Values{"id_token_hint": {tk.IDToken}, "client_id": {"frag"}, "post_logout_redirect_uri": {bye}}
		}},
		{"client_id of an unknown client", func(e *server.Env, tk server.Tokens) url.Values {
			return url.Values{"id_token_hint": {tk.IDToken}, "client_id": {"nobody"}}
		}},
		{"unregistered return URL", func(e *server.Env, tk server.Tokens) url.Values {
			return url.Values{"id_token_hint": {tk.IDToken}, "client_id": {"web"}, "post_logout_redirect_uri": {"https://evil.example.com/bye"}}
		}},
		{"unregistered return URL without client_id", func(e *server.Env, tk server.Tokens) url.Values {
			return url.Values{"id_token_hint": {tk.IDToken}, "post_logout_redirect_uri": {"https://evil.example.com/bye"}}
		}},
		{"a URL of another client", func(e *server.Env, tk server.Tokens) url.Values {
			return url.Values{"id_token_hint": {tk.IDToken}, "post_logout_redirect_uri": {server.ClientFragment.RedirectURI}}
		}},
		{"a URL differing in case", func(e *server.Env, tk server.Tokens) url.Values {
			return url.Values{"id_token_hint": {tk.IDToken}, "post_logout_redirect_uri": {strings.ToUpper(bye)}}
		}},
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, row := range rows {
			t.Run(method+" "+row.name, func(t *testing.T) {
				e := logoutEnv(t)
				tk := exchange(t, e, app)
				wantRefusal(t, logout(t, e, method, row.v(e, tk), nil))
				wantAlive(t, e, app, tk.RefreshToken)
			})
		}
	}
}

// Covers: FR-11 (part), FR-28 (part)
// Acceptance: Logout without hint
func TestLogoutWithoutHint(t *testing.T) {
	app := server.ClientQuery
	frag := server.ClientFragment.RedirectURI
	rows := []struct {
		name string
		v    url.Values
		want string // a redirect location, "" for the signed-out page, "refused" for the error page
	}{
		{"client_id with its registered URL", url.Values{"client_id": {"web"}, "post_logout_redirect_uri": {bye}, "state": {"s1"}}, bye + "?state=s1"},
		{"client_id with the URL of another client", url.Values{"client_id": {"web"}, "post_logout_redirect_uri": {frag}}, "refused"},
		{"unknown client_id with a URL", url.Values{"client_id": {"nobody"}, "post_logout_redirect_uri": {bye}}, "refused"},
		{"client_id alone", url.Values{"client_id": {"web"}}, ""},
		{"post_logout_redirect_uri alone, registered for some client", url.Values{"post_logout_redirect_uri": {frag}, "state": {"s1"}}, ""},
		{"post_logout_redirect_uri alone, registered for no client", url.Values{"post_logout_redirect_uri": {"https://evil.example.com/bye"}}, ""},
		{"no return URL at all", url.Values{}, ""},
		{"legacy name, not in logout.redirect_params", url.Values{"redirect_uri": {"https://evil.example.com/bye"}}, ""},
		{"an empty return URL", url.Values{"post_logout_redirect_uri": {""}, "state": {"s1"}}, ""},
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, row := range rows {
			t.Run(method+" "+row.name, func(t *testing.T) {
				e := logoutEnv(t)
				tk := exchange(t, e, app)
				r := logout(t, e, method, row.v, nil)
				switch row.want {
				case "refused":
					wantRefusal(t, r)
				case "":
					wantSignedOut(t, r)
				default:
					wantRedirect(t, r, row.want)
				}
				wantAlive(t, e, app, tk.RefreshToken) // nothing identifies a session
			})
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method+" the legacy name redirect_uri", func(t *testing.T) {
			e := logoutEnv(t)
			tk := exchange(t, e, app)
			e.ReloadServer(t, func(y string) string {
				return y + "logout:\n  redirect_params: [post_logout_redirect_uri, redirect_uri]\n"
			})
			wantRedirect(t, logout(t, e, method, url.Values{"redirect_uri": {frag}, "state": {"s1"}}, nil), frag+"?state=s1")
			wantRefusal(t, logout(t, e, method, url.Values{"redirect_uri": {"https://evil.example.com/bye"}}, nil))
			// both names: the standard one counts, so there is no redirect
			wantSignedOut(t, logout(t, e, method, url.Values{"post_logout_redirect_uri": {bye}, "redirect_uri": {frag}}, nil))
			wantSignedOut(t, logout(t, e, method, url.Values{"post_logout_redirect_uri": {"https://evil.example.com/bye"}, "redirect_uri": {frag}}, nil))
			// the standard name alone: no redirect without a hint or a client_id
			wantSignedOut(t, logout(t, e, method, url.Values{"post_logout_redirect_uri": {frag}}, nil))
			// with a client_id the standard name redirects, as before
			wantRedirect(t, logout(t, e, method, url.Values{"client_id": {"web"}, "post_logout_redirect_uri": {bye}}, nil), bye)
			wantAlive(t, e, app, tk.RefreshToken)
		})
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method+" the standard name wins whatever the order of the list", func(t *testing.T) {
			e := logoutEnv(t)
			e.ReloadServer(t, func(y string) string {
				return y + "logout:\n  redirect_params: [redirect_uri, post_logout_redirect_uri]\n"
			})
			wantSignedOut(t, logout(t, e, method, url.Values{"post_logout_redirect_uri": {bye}, "redirect_uri": {frag}}, nil))
			wantRedirect(t, logout(t, e, method, url.Values{"redirect_uri": {frag}}, nil), frag)
		})
		t.Run(method+" without the standard name only redirect_uri is read", func(t *testing.T) {
			e := logoutEnv(t)
			e.ReloadServer(t, func(y string) string { return y + "logout:\n  redirect_params: [redirect_uri]\n" })
			wantRedirect(t, logout(t, e, method, url.Values{"redirect_uri": {frag}, "post_logout_redirect_uri": {bye}}, nil), frag)
			wantSignedOut(t, logout(t, e, method, url.Values{"post_logout_redirect_uri": {bye}}, nil))
			wantRefusal(t, logout(t, e, method, url.Values{"redirect_uri": {"https://evil.example.com/bye"}}, nil))
		})
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method+" redirect_params from the configuration", func(t *testing.T) {
			e := logoutEnv(t)
			tk := exchange(t, e, app)
			e.ReloadServer(t, func(y string) string { return y + "logout:\n  redirect_params: [return_to, redirect_uri]\n" })
			wantRedirect(t, logout(t, e, method, url.Values{"redirect_uri": {frag}}, nil), frag)
			wantRedirect(t, logout(t, e, method, url.Values{"return_to": {bye}, "redirect_uri": {frag}}, nil), bye) // the first name wins
			wantRedirect(t, logout(t, e, method, url.Values{"client_id": {"web"}, "return_to": {bye}}, nil), bye)
			wantSignedOut(t, logout(t, e, method, url.Values{"post_logout_redirect_uri": {bye}}, nil)) // no longer a name
			wantRefusal(t, logout(t, e, method, url.Values{"return_to": {"https://evil.example.com/bye"}}, nil))
			wantAlive(t, e, app, tk.RefreshToken)
		})
	}
}

// Covers: FR-11 (part)
// Acceptance: Logout from the app
func TestLogoutFromTheApp(t *testing.T) {
	app := server.ClientQuery
	post := func(e *server.Env, v url.Values, h http.Header) server.Response {
		return logout(t, e, http.MethodPost, v, h)
	}
	t.Run("a refresh token with its client_id", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		other := exchange(t, e, app)
		r := post(e, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}}, nil)
		if r.Code != http.StatusNoContent || r.Body != "" || r.Header.Get("Location") != "" {
			t.Fatalf("%d %v %q", r.Code, r.Header, r.Body)
		}
		wantRevoked(t, e, app, tk.RefreshToken)
		wantAlive(t, e, app, other.RefreshToken)
	})
	t.Run("a rotated refresh token ends the session of its successor", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		next := wantTokens(t, refresh(t, e, app, tk.RefreshToken))
		if r := post(e, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}}, nil); r.Code != 204 {
			t.Fatalf("%d %q", r.Code, r.Body)
		}
		wantRevoked(t, e, app, next.RefreshToken)
	})
	t.Run("a repeat", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		for range 2 {
			if r := post(e, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}}, nil); r.Code != 204 {
				t.Fatalf("%d %q", r.Code, r.Body)
			}
		}
	})
	t.Run("with another client's id", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		r := post(e, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {"frag"}}, nil)
		wantError(t, r, 400, "invalid_grant")
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("an unknown refresh token", func(t *testing.T) {
		e := logoutEnv(t)
		wantError(t, post(e, url.Values{"refresh_token": {"nope"}, "client_id": {app.ID}}, nil), 400, "invalid_grant")
	})
	t.Run("an unknown client", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		wantError(t, post(e, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {"nobody"}}, nil), 400, "invalid_client")
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("a refresh token of a realm with no store rows", func(t *testing.T) {
		e := logoutEnv(t)
		wantError(t, post(e, url.Values{"refresh_token": {"nope"}, "client_id": {app.ID}}, nil), 400, "invalid_grant")
	})
	t.Run("a JWT refresh token", func(t *testing.T) {
		e := logoutEnv(t, server.WithRefreshFormat("jwt"))
		tk := exchange(t, e, app)
		if r := post(e, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}}, nil); r.Code != 204 {
			t.Fatalf("%d %q", r.Code, r.Body)
		}
		wantRevoked(t, e, app, tk.RefreshToken)
	})
	t.Run("a confidential client authenticates", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchangeConfidential(t, e, server.ClientConfidential)
		v := url.Values{"refresh_token": {tk.RefreshToken}}
		wantError(t, post(e, v, nil), 400, "invalid_client")
		wantError(t, post(e, v, basic("srv", "wrong")), 401, "invalid_client")
		if r := post(e, v, basic("srv", e.Secret("srv"))); r.Code != 204 {
			t.Fatalf("%d %q", r.Code, r.Body)
		}
		f := server.RefreshForm(server.ClientConfidential, tk.RefreshToken)
		wantError(t, e.NewClient().PostToken(t, f, basic("srv", e.Secret("srv"))), 400, "invalid_grant")
	})
	t.Run("a bearer access token", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		other := exchange(t, e, app)
		r := post(e, nil, http.Header{"Authorization": {"Bearer " + tk.AccessToken}})
		if r.Code != http.StatusNoContent || r.Body != "" {
			t.Fatalf("%d %v %q", r.Code, r.Header, r.Body)
		}
		wantRevoked(t, e, app, tk.RefreshToken)
		wantAlive(t, e, app, other.RefreshToken)
		// The access token itself stays valid until it expires (SEC-14).
		if r := userinfo(t, e, http.MethodGet, tk.AccessToken, nil); r.Code != 200 {
			t.Errorf("userinfo %d", r.Code)
		}
	})
	t.Run("a bearer token that is not an access token", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		for name, h := range map[string]http.Header{
			"id token": {"Authorization": {"Bearer " + tk.IDToken}},
			"garbage":  {"Authorization": {"Bearer garbage"}},
			"no token": {"Authorization": {"Bearer"}},
		} {
			r := post(e, nil, h)
			if r.Code != 401 || r.Header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
				t.Errorf("%s: %d %v %q", name, r.Code, r.Header, r.Body)
			}
		}
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("a disabled user", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		e.SetDisabled(t, true)
		r := post(e, nil, http.Header{"Authorization": {"Bearer " + tk.AccessToken}})
		if r.Code != 401 {
			t.Fatalf("%d %q", r.Code, r.Body)
		}
	})
	t.Run("a GET carries no app request", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		r := logout(t, e, http.MethodGet, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}}, http.Header{"Authorization": {"Bearer " + tk.AccessToken}})
		wantSignedOut(t, r)
		wantAlive(t, e, app, tk.RefreshToken)
	})
}

// refreshRevoked reads the stored state of a refresh token.
func refreshRevoked(t *testing.T, e *server.Env, rt string) bool {
	t.Helper()
	var revoked bool
	err := e.Store.Read(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(context.Background(), "main")
		if err != nil {
			return err
		}
		row, err := tx.RefreshTokens().FindByHash(context.Background(), rid, secure.HashOf(rt))
		revoked = !row.RevokedAt.IsZero()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return revoked
}

func auditRows(t *testing.T, e *server.Env) int {
	t.Helper()
	var n int
	err := e.Store.Read(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(context.Background(), "main")
		if err != nil {
			return err
		}
		rows, err := tx.Audit().List(context.Background(), rid, time.Time{})
		n = len(rows)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// Covers: FR-11 (part)
// Acceptance: Logout edge cases
func TestLogoutEdgeCases(t *testing.T) {
	app := server.ClientQuery
	t.Run("an expired own refresh token still revokes the session", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		e.Clock.Advance(100000 * time.Hour)
		if r := logout(t, e, http.MethodPost, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}}, nil); r.Code != 204 {
			t.Fatalf("%d %q", r.Code, r.Body)
		}
		if !refreshRevoked(t, e, tk.RefreshToken) {
			t.Error("not revoked")
		}
	})
	t.Run("an already revoked own refresh token gets 204", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		v := url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}}
		for range 2 {
			if r := logout(t, e, http.MethodPost, v, nil); r.Code != 204 {
				t.Fatalf("%d %q", r.Code, r.Body)
			}
		}
	})
	t.Run("another client's or an unknown token revokes nothing", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		wantError(t, logout(t, e, http.MethodPost, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {"frag"}}, nil), 400, "invalid_grant")
		wantError(t, logout(t, e, http.MethodPost, url.Values{"refresh_token": {"nope"}, "client_id": {app.ID}}, nil), 400, "invalid_grant")
		if refreshRevoked(t, e, tk.RefreshToken) {
			t.Error("revoked")
		}
	})
	t.Run("a disabled realm does not block logout", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		e.Reload(t, func(y string) string { return strings.Replace(y, "name: main\n", "name: main\nenabled: false\n", 1) })
		v := url.Values{"id_token_hint": {tk.IDToken}, "post_logout_redirect_uri": {bye}}
		wantRedirect(t, logout(t, e, http.MethodGet, v, nil), bye)
		if !refreshRevoked(t, e, tk.RefreshToken) {
			t.Error("not revoked")
		}
	})
	t.Run("an info log line and no audit row", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		before := auditRows(t, e)
		e.Logs.Reset()
		logout(t, e, http.MethodGet, url.Values{"id_token_hint": {tk.IDToken}}, nil)
		if !strings.Contains(e.Logs.String(), `"msg":"logout"`) || !strings.Contains(e.Logs.String(), `"level":"INFO"`) {
			t.Errorf("log %q", e.Logs.String())
		}
		if got := auditRows(t, e); got != before {
			t.Errorf("audit rows %d, want %d", got, before)
		}
	})
	t.Run("a store failure revokes nothing", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		e.Faults.Fail("Refresh.RevokeSession", store.ErrUnavailable)
		r := logout(t, e, http.MethodGet, url.Values{"id_token_hint": {tk.IDToken}, "post_logout_redirect_uri": {bye}}, nil)
		if r.Code != 503 || r.Header.Get("Location") != "" {
			t.Errorf("%d %v", r.Code, r.Header)
		}
		if refreshRevoked(t, e, tk.RefreshToken) {
			t.Error("revoked")
		}
	})
}

// Covers: FR-11 (part)
// Acceptance: Logout routing
func TestLogoutRouting(t *testing.T) {
	app := server.ClientQuery
	post := func(e *server.Env, v url.Values, h http.Header) server.Response {
		return logout(t, e, http.MethodPost, v, h)
	}
	t.Run("a scheme other than Bearer is not a bearer request", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		wantSignedOut(t, post(e, nil, http.Header{"Authorization": {"Basic " + tk.AccessToken}}))
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("the Bearer scheme is case-insensitive", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		if r := post(e, nil, http.Header{"Authorization": {"bEaReR " + tk.AccessToken}}); r.Code != 204 {
			t.Fatalf("%d %q", r.Code, r.Body)
		}
		wantRevoked(t, e, app, tk.RefreshToken)
	})
	t.Run("a refresh token wins over a Bearer header", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		other := exchange(t, e, app)
		r := post(e, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}}, http.Header{"Authorization": {"Bearer " + other.AccessToken}})
		if r.Code != 204 {
			t.Fatalf("%d %q", r.Code, r.Body)
		}
		wantRevoked(t, e, app, tk.RefreshToken)
		wantAlive(t, e, app, other.RefreshToken)
	})
	t.Run("an empty refresh_token is absent", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		wantSignedOut(t, post(e, url.Values{"refresh_token": {""}}, nil))
		if r := post(e, url.Values{"refresh_token": {""}}, http.Header{"Authorization": {"Bearer " + tk.AccessToken}}); r.Code != 204 {
			t.Fatalf("%d %q", r.Code, r.Body)
		}
		wantRevoked(t, e, app, tk.RefreshToken)
	})
	t.Run("empty values are absent in an RP-initiated request", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		v := url.Values{"id_token_hint": {""}, "client_id": {""}, "post_logout_redirect_uri": {""}, "state": {""}}
		wantSignedOut(t, logout(t, e, http.MethodGet, v, nil))
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("a repeated refresh_token", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		r := post(e, url.Values{"refresh_token": {tk.RefreshToken, tk.RefreshToken}, "client_id": {app.ID}}, nil)
		wantError(t, r, 400, "invalid_request")
		wantAlive(t, e, app, tk.RefreshToken)
	})
	t.Run("a repeated client_id of a refresh token request", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		r := post(e, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID, app.ID}}, nil)
		wantError(t, r, 400, "invalid_request")
		wantAlive(t, e, app, tk.RefreshToken)
	})
}

// Covers: FR-11 (part), FR-28 (part)
// Acceptance: Logout repeated parameters
func TestLogoutRefusesRepeatedParameters(t *testing.T) {
	app := server.ClientQuery
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, name := range []string{"id_token_hint", "client_id", "post_logout_redirect_uri", "redirect_uri", "state"} {
			t.Run(method+" "+name, func(t *testing.T) {
				e := logoutEnv(t)
				e.ReloadServer(t, func(y string) string {
					return y + "logout:\n  redirect_params: [post_logout_redirect_uri, redirect_uri]\n"
				})
				tk := exchange(t, e, app)
				v := url.Values{"id_token_hint": {tk.IDToken}, "client_id": {app.ID}, "post_logout_redirect_uri": {bye}, "state": {"s1"}}
				if name == "redirect_uri" {
					v.Set(name, bye)
				}
				v.Add(name, v.Get(name))
				wantRefusal(t, logout(t, e, method, v, nil))
				wantAlive(t, e, app, tk.RefreshToken)
			})
		}
	}
	t.Run("a repeated name with an empty first value", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		v := url.Values{"post_logout_redirect_uri": {"", bye}}
		wantRefusal(t, logout(t, e, http.MethodGet, v, nil))
		wantAlive(t, e, app, tk.RefreshToken)
	})
}

// Covers: SEC-34 (part)
// Acceptance: Logout lookups
func TestLogoutLooksBeforeItWrites(t *testing.T) {
	app := server.ClientQuery
	post := func(e *server.Env, rt, client string) server.Response {
		return logout(t, e, http.MethodPost, url.Values{"refresh_token": {rt}, "client_id": {client}}, nil)
	}
	// writes runs f and returns how many write transactions it started.
	writes := func(e *server.Env, f func()) int {
		before := e.Faults.Writes()
		f()
		return e.Faults.Writes() - before
	}
	t.Run("a made-up token", func(t *testing.T) {
		e := logoutEnv(t)
		var r server.Response
		if n := writes(e, func() { r = post(e, "nope", app.ID) }); n != 0 {
			t.Errorf("%d write transactions, want 0", n)
		}
		wantError(t, r, 400, "invalid_grant")
	})
	t.Run("another client's token", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, server.ClientFragment)
		var r server.Response
		if n := writes(e, func() { r = post(e, tk.RefreshToken, app.ID) }); n != 0 {
			t.Errorf("%d write transactions, want 0", n)
		}
		wantError(t, r, 400, "invalid_grant")
		wantTokens(t, refresh(t, e, server.ClientFragment, tk.RefreshToken))
	})
	t.Run("a token of a revoked session", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		if r := post(e, tk.RefreshToken, app.ID); r.Code != http.StatusNoContent {
			t.Fatalf("first logout: %d %q", r.Code, r.Body)
		}
		var r server.Response
		if n := writes(e, func() { r = post(e, tk.RefreshToken, app.ID) }); n != 0 {
			t.Errorf("%d write transactions, want 0", n)
		}
		if r.Code != http.StatusNoContent {
			t.Errorf("second logout: %d %q, want 204", r.Code, r.Body)
		}
	})
	t.Run("a live token revokes its session with one write", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		other := exchange(t, e, app)
		var r server.Response
		if n := writes(e, func() { r = post(e, tk.RefreshToken, app.ID) }); n != 1 {
			t.Errorf("%d write transactions, want 1", n)
		}
		if r.Code != http.StatusNoContent || r.Body != "" {
			t.Fatalf("%d %v %q", r.Code, r.Header, r.Body)
		}
		wantRevoked(t, e, app, tk.RefreshToken)
		wantAlive(t, e, app, other.RefreshToken)
	})
	t.Run("a lookup that fails is unavailable and writes nothing", func(t *testing.T) {
		e := logoutEnv(t)
		tk := exchange(t, e, app)
		e.Faults.Fail("Refresh.SessionLive", store.ErrUnavailable)
		var r server.Response
		if n := writes(e, func() { r = post(e, tk.RefreshToken, app.ID) }); n != 0 {
			t.Errorf("%d write transactions, want 0", n)
		}
		if got := wantJSONError(t, r); r.Code != http.StatusServiceUnavailable || got != "temporarily_unavailable" {
			t.Errorf("%d %q", r.Code, r.Body)
		}
		e.Faults.Fail("Refresh.SessionLive", nil)
		wantAlive(t, e, app, tk.RefreshToken)
	})
}

// Covers: FR-11 (part), SEC-20 (part)
func TestLogoutStoreFailures(t *testing.T) {
	app := server.ClientQuery
	for _, row := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"unavailable", store.ErrUnavailable, 503, "temporarily_unavailable"},
		{"other", errors.New("boom"), 500, "server_error"},
	} {
		t.Run(row.name, func(t *testing.T) {
			e := logoutEnv(t)
			tk := exchange(t, e, app)

			e.Faults.Fail("Refresh.FindByHash", row.err)
			r := logout(t, e, http.MethodPost, url.Values{"refresh_token": {tk.RefreshToken}, "client_id": {app.ID}}, nil)
			if got := wantJSONError(t, r); r.Code != row.status || got != row.code {
				t.Errorf("refresh token: %d %q", r.Code, r.Body)
			}
			e.Faults.Fail("Refresh.FindByHash", nil)

			e.Faults.Fail("Refresh.RevokeSession", row.err)
			r = logout(t, e, http.MethodPost, nil, http.Header{"Authorization": {"Bearer " + tk.AccessToken}})
			if got := wantJSONError(t, r); r.Code != row.status || got != row.code {
				t.Errorf("bearer: %d %q", r.Code, r.Body)
			}
			r = logout(t, e, http.MethodGet, url.Values{"id_token_hint": {tk.IDToken}}, nil)
			if r.Code != row.status || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") || r.Header.Get("Location") != "" {
				t.Errorf("hint: %d %v", r.Code, r.Header)
			}
			e.Faults.Fail("Refresh.RevokeSession", nil)
			wantAlive(t, e, app, tk.RefreshToken)

			e.Faults.Fail("Users.Get", row.err)
			r = logout(t, e, http.MethodPost, nil, http.Header{"Authorization": {"Bearer " + tk.AccessToken}})
			if got := wantJSONError(t, r); r.Code != row.status || got != row.code {
				t.Errorf("bearer user lookup: %d %q", r.Code, r.Body)
			}
		})
	}
}

func wantJSONError(t *testing.T, r server.Response) string {
	t.Helper()
	var b map[string]string
	_ = json.Unmarshal([]byte(r.Body), &b)
	return b["error"]
}

// Covers: FR-11 (part), FR-58 (part)
// Acceptance: Wrong method (part)
func TestLogoutWrongMethods(t *testing.T) {
	e := logoutEnv(t)
	tk := exchange(t, e, server.ClientQuery)
	for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, http.MethodHead} {
		r := e.NewClient().Request(t, m, logoutURL+"?id_token_hint="+url.QueryEscape(tk.IDToken), "", nil)
		if r.Code != 405 || r.Header.Get("Allow") != "GET, POST" || (m != http.MethodHead && !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html")) {
			t.Errorf("%s: %d %v", m, r.Code, r.Header)
		}
	}
	wantAlive(t, e, server.ClientQuery, tk.RefreshToken)
}

// Covers: FR-11 (part)
func TestLogoutUnroutedRequest(t *testing.T) {
	// Without routing information the answer is the server error.
	w := httptest.NewRecorder()
	oidc.NewLogout(oidc.LogoutConfig{}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/main/logout", nil))
	if w.Code != 500 {
		t.Fatalf("status %d", w.Code)
	}
}
