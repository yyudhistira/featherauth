package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/oidc"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

func userinfo(t *testing.T, e *server.Env, method, access string, h http.Header) server.Response {
	t.Helper()
	hh := http.Header{}
	if access != "" {
		hh.Set("Authorization", "Bearer "+access)
	}
	for k, v := range h {
		hh[k] = v
	}
	return e.NewClient().Request(t, method, server.Issuer+"/userinfo", "", hh)
}

func claimsOf(t *testing.T, r server.Response) map[string]any {
	t.Helper()
	if r.Code != 200 {
		t.Fatalf("status %d body %q", r.Code, r.Body)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	return m
}

func renameUser(t *testing.T, e *server.Env, name string) {
	t.Helper()
	ctx := context.Background()
	err := e.Store.Write(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		ident, err := tx.Identities().Find(ctx, rid, "google", "1001")
		if err != nil {
			return err
		}
		u, err := tx.Users().Get(ctx, rid, ident.UserID)
		if err != nil {
			return err
		}
		u.Name = name
		return tx.Users().Update(ctx, u)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Covers: FR-09 (part)
// Acceptance: Userinfo methods (part)
func TestUserinfoGetAndPostGiveTheSameClaims(t *testing.T) {
	e := server.New(t)
	g := e.Exchange(t, server.ClientQuery, e.Login(t, server.ClientQuery))
	get := userinfo(t, e, http.MethodGet, g.AccessToken, nil)
	post := userinfo(t, e, http.MethodPost, g.AccessToken, nil)
	want := map[string]any{"sub": claimsOf(t, get)["sub"], "name": "Ann Lee", "email": "ann@example.com", "email_verified": true, "preferred_username": "ann@example.com"}
	if want["sub"] == "" || want["sub"] == nil {
		t.Fatalf("no sub in %v", get.Body)
	}
	for _, r := range []server.Response{get, post} {
		if got := claimsOf(t, r); !reflect.DeepEqual(got, want) {
			t.Errorf("claims %v, want %v", got, want)
		}
		if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("headers %v", r.Header)
		}
	}
}

// Covers: FR-09 (part)
// Acceptance: Userinfo methods
func TestUserinfoInvalidTokenAndMethods(t *testing.T) {
	e := server.New(t)
	g := e.Exchange(t, server.ClientQuery, e.Login(t, server.ClientQuery))
	t.Run("GET and POST give the same claims", func(t *testing.T) {
		get := claimsOf(t, userinfo(t, e, http.MethodGet, g.AccessToken, nil))
		post := claimsOf(t, userinfo(t, e, http.MethodPost, g.AccessToken, nil))
		if len(get) == 0 || !reflect.DeepEqual(get, post) {
			t.Errorf("GET %v, POST %v", get, post)
		}
	})
	for _, row := range []struct {
		name, method, token string
	}{
		{"GET no token", http.MethodGet, ""},
		{"GET garbage", http.MethodGet, "garbage"},
		{"POST garbage", http.MethodPost, "garbage"},
		{"GET id token", http.MethodGet, g.IDToken},
		{"POST refresh token", http.MethodPost, g.RefreshToken},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := userinfo(t, e, row.method, row.token, nil)
			if r.Code != 401 || r.Header.Get("WWW-Authenticate") != `Bearer error="invalid_token"` || !strings.Contains(r.Body, `"invalid_token"`) {
				t.Errorf("%d %v %q", r.Code, r.Header, r.Body)
			}
		})
	}
	t.Run("other methods", func(t *testing.T) {
		r := userinfo(t, e, http.MethodDelete, g.AccessToken, nil)
		if r.Code != 405 || r.Header.Get("Allow") != "GET, POST, OPTIONS" {
			t.Errorf("%d %v", r.Code, r.Header)
		}
	})
	t.Run("expired", func(t *testing.T) {
		e.Clock.Advance(16 * time.Minute)
		if r := userinfo(t, e, http.MethodGet, g.AccessToken, nil); r.Code != 401 {
			t.Errorf("%d", r.Code)
		}
	})
}

// Covers: FR-09 (part)
func TestUserinfoStoreFailures(t *testing.T) {
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
			e := server.New(t)
			g := e.Exchange(t, server.ClientQuery, e.Login(t, server.ClientQuery))
			e.Faults.Fail("Users.Get", row.err)
			r := userinfo(t, e, http.MethodGet, g.AccessToken, nil)
			var b map[string]string
			_ = json.Unmarshal([]byte(r.Body), &b)
			if r.Code != row.status || b["error"] != row.code {
				t.Errorf("%d %q", r.Code, r.Body)
			}
		})
	}
}

// Covers: FR-22 (part)
// Acceptance: Scopes do not filter claims (part)
func TestUserinfoIgnoresScopes(t *testing.T) {
	e := server.New(t)
	g := e.Exchange(t, server.ClientQuery, e.Login(t, server.ClientQuery, "scope", "openid"))
	m := claimsOf(t, userinfo(t, e, http.MethodGet, g.AccessToken, nil))
	for _, k := range []string{"name", "email", "preferred_username"} {
		if m[k] == nil {
			t.Errorf("claim %s missing in %v", k, m)
		}
	}
}

// Covers: FR-22 (part)
// Acceptance: User data (part)
func TestUserinfoClaimsComeFromTheStoredProfile(t *testing.T) {
	e := server.New(t)
	g := e.Exchange(t, server.ClientQuery, e.Login(t, server.ClientQuery))
	renameUser(t, e, "Ann Renamed")
	if m := claimsOf(t, userinfo(t, e, http.MethodGet, g.AccessToken, nil)); m["name"] != "Ann Renamed" {
		t.Errorf("name %v, the token's claim was used", m["name"])
	}
	t.Run("only the selected claims", func(t *testing.T) {
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "keys:\n", "user_data:\n  claims: [email, allowed-origins]\nkeys:\n", 1)
		})
		want := map[string]any{"sub": nil, "email": "ann@example.com", "allowed-origins": []any{"https://app.example.com"}}
		got := claimsOf(t, userinfo(t, e, http.MethodGet, g.AccessToken, nil))
		if got["sub"] == nil || got["sub"] == "" {
			t.Errorf("no sub: %v", got)
		}
		want["sub"] = got["sub"]
		if !reflect.DeepEqual(got, want) {
			t.Errorf("claims %v, want %v", got, want)
		}
	})
	t.Run("a claim with no value is omitted", func(t *testing.T) {
		renameUser(t, e, "")
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "[email, allowed-origins]", "[name, email_verified]", 1)
		})
		got := claimsOf(t, userinfo(t, e, http.MethodGet, g.AccessToken, nil))
		if _, ok := got["name"]; ok || got["email_verified"] != true {
			t.Errorf("claims %v", got)
		}
	})
	t.Run("an empty list leaves sub", func(t *testing.T) {
		e.Reload(t, func(y string) string { return strings.Replace(y, "[name, email_verified]", "[]", 1) })
		got := claimsOf(t, userinfo(t, e, http.MethodGet, g.AccessToken, nil))
		if len(got) != 1 || got["sub"] == nil {
			t.Errorf("claims %v", got)
		}
	})
}

// Covers: FR-09 (part), SEC-20 (part)
// Acceptance: Bearer header errors
func TestUserinfoBearerHeaderErrors(t *testing.T) {
	e := server.New(t)
	g := e.Exchange(t, server.ClientQuery, e.Login(t, server.ClientQuery))
	const invalid = `Bearer error="invalid_token"`
	for _, row := range []struct {
		name string
		hdr  http.Header
	}{
		{"no header", nil},
		{"two headers", http.Header{"Authorization": {"Bearer " + g.AccessToken, "Bearer " + g.AccessToken}}},
		{"another scheme", http.Header{"Authorization": {"Basic " + g.AccessToken}}},
		{"scheme without token", http.Header{"Authorization": {"Bearer"}}},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := userinfo(t, e, http.MethodGet, "", row.hdr)
			if r.Code != 401 || r.Header.Get("WWW-Authenticate") != invalid {
				t.Errorf("%d %v %q", r.Code, r.Header, r.Body)
			}
		})
	}
	t.Run("scheme in lower case", func(t *testing.T) {
		claimsOf(t, userinfo(t, e, http.MethodGet, "", http.Header{"Authorization": {"bearer " + g.AccessToken}}))
	})
	for _, row := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"store unavailable", store.ErrUnavailable, 503, "temporarily_unavailable"},
		{"store fails", errors.New("boom"), 500, "server_error"},
	} {
		t.Run(row.name, func(t *testing.T) {
			e.Faults.Fail("Users.Get", row.err)
			r := userinfo(t, e, http.MethodGet, g.AccessToken, nil)
			var b map[string]string
			_ = json.Unmarshal([]byte(r.Body), &b)
			if r.Code != row.status || b["error"] != row.code || strings.Contains(r.Header.Get("WWW-Authenticate"), "invalid_token") {
				t.Errorf("%d %v %q", r.Code, r.Header, r.Body)
			}
		})
	}
}

// Covers: FR-26 (part), SEC-18 (part)
// Acceptance: CORS (part)
// Acceptance: Userinfo origin
func TestUserinfoCORS(t *testing.T) {
	const own, other = "https://app.example.com", "https://frag.example.com"
	e := server.New(t)
	g := e.Exchange(t, server.ClientQuery, e.Login(t, server.ClientQuery))
	origin := func(o string) http.Header { return http.Header{"Origin": {o}} }

	t.Run("preflight", func(t *testing.T) {
		r := e.NewClient().Request(t, http.MethodOptions, server.Issuer+"/userinfo", "", http.Header{
			"Origin": {other}, "Access-Control-Request-Method": {"GET"},
		})
		if r.Code != 204 || r.Header.Get("Access-Control-Allow-Origin") != other || r.Header.Get("Access-Control-Allow-Methods") != "GET, POST, OPTIONS" {
			t.Errorf("%d %v", r.Code, r.Header)
		}
	})
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		t.Run(m+" from the token's client origin", func(t *testing.T) {
			r := userinfo(t, e, m, g.AccessToken, origin(own))
			claimsOf(t, r)
			if r.Header.Get("Access-Control-Allow-Origin") != own || r.Header.Get("Vary") != "Origin" {
				t.Errorf("headers %v", r.Header)
			}
		})
	}
	t.Run("from another client's origin", func(t *testing.T) {
		r := userinfo(t, e, http.MethodGet, g.AccessToken, origin(other))
		if r.Header.Get("Access-Control-Allow-Origin") != "" || r.Header.Get("Vary") != "Origin" {
			t.Errorf("headers %v", r.Header)
		}
		if got := claimsOf(t, r); got["email"] != "ann@example.com" { // 200 with the claims
			t.Errorf("claims %v", got)
		}
	})
	t.Run("from an unregistered origin", func(t *testing.T) {
		r := userinfo(t, e, http.MethodGet, g.AccessToken, origin("https://evil.example.com"))
		if r.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("headers %v", r.Header)
		}
		if got := claimsOf(t, r); got["email"] != "ann@example.com" {
			t.Errorf("claims %v", got)
		}
	})
	t.Run("an invalid token gets no allow header", func(t *testing.T) {
		r := userinfo(t, e, http.MethodGet, "garbage", origin(own))
		if r.Code != 401 || r.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%d %v", r.Code, r.Header)
		}
	})
	t.Run("a client removed since the login allows no origin", func(t *testing.T) {
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "keys:\n", "user_data:\n  claims: [email, allowed-origins]\nkeys:\n", 1)
		})
		before := claimsOf(t, userinfo(t, e, http.MethodGet, g.AccessToken, origin(own)))
		if before["allowed-origins"] == nil {
			t.Fatalf("allowed-origins missing before the removal: %v", before)
		}
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "  web:\n    redirect_uris: [https://app.example.com/callback]\n    web_origins: [https://app.example.com]\n", "", 1)
		})
		if _, ok := e.Realm.Clients[config.ClientID("web")]; ok {
			t.Fatal("client not removed")
		}
		r := userinfo(t, e, http.MethodGet, g.AccessToken, origin(own))
		if r.Code != 200 || r.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%d %v", r.Code, r.Header)
		}
		if got := claimsOf(t, r); got["email"] != "ann@example.com" || got["allowed-origins"] != nil {
			t.Errorf("claims %v", got)
		}
	})
}

// Covers: FR-09 (part)
func TestUserinfoOtherRequests(t *testing.T) {
	t.Run("a plain OPTIONS request", func(t *testing.T) {
		e := server.New(t)
		r := e.NewClient().Request(t, http.MethodOptions, server.Issuer+"/userinfo", "", nil)
		if r.Code != 204 {
			t.Errorf("status %d", r.Code)
		}
	})
	t.Run("a request the router did not route", func(t *testing.T) {
		u := oidc.NewUserinfo(oidc.UserinfoConfig{})
		w := httptest.NewRecorder()
		u.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/main/userinfo", nil))
		if w.Code != 500 {
			t.Errorf("status %d", w.Code)
		}
	})
}
