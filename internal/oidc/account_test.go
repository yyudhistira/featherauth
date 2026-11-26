package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

func deleteAccount(t *testing.T, e *server.Env, access string) server.Response {
	t.Helper()
	return deleteAccountWith(t, e, http.MethodDelete, access)
}

func deleteAccountWith(t *testing.T, e *server.Env, method, access string) server.Response {
	t.Helper()
	h := http.Header{}
	if access != "" {
		h.Set("Authorization", "Bearer "+access)
	}
	return e.NewClient().Request(t, method, server.Issuer+"/account", "", h)
}

// userExists reports whether a user of the provider identity is stored.
func userExists(t *testing.T, e *server.Env, prov config.ProviderKey, sub string) bool {
	t.Helper()
	ctx := context.Background()
	var found bool
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		_, err = tx.Identities().Find(ctx, rid, prov, sub)
		if err == nil {
			found = true
		} else if err == store.ErrNotFound {
			err = nil
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func wantBearerError(t *testing.T, r server.Response, status int, header, code string) {
	t.Helper()
	if r.Code != status || r.Header.Get("WWW-Authenticate") != header || !strings.Contains(r.Body, `"`+code+`"`) {
		t.Fatalf("%d %q %q, want %d %q %q", r.Code, r.Header.Get("WWW-Authenticate"), r.Body, status, header, code)
	}
}

const invalidTokenHeader = `Bearer error="invalid_token"`

// Covers: FR-13
// Acceptance: Account deletion
func TestAccountDeleteRightAfterLogin(t *testing.T) {
	e := server.New(t)
	app := server.ClientDelete
	e.Mocks["apple"].SetUser(mockidp.User{Sub: "apple-1", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
	res := e.NewClient().Login(t, server.Authorize(app, "apple"))
	g := e.Exchange(t, app, res)

	live := wantTokens(t, refresh(t, e, app, g.RefreshToken)) // a successor of the login's token
	g2 := e.Exchange(t, app, e.NewClient().Login(t, server.Authorize(app, "apple")))
	stored := e.Mocks["apple"].RefreshToken() // the login keeps the newest token, sealed

	t.Run("an ID token is not a bearer token", func(t *testing.T) {
		wantBearerError(t, deleteAccount(t, e, g.IDToken), 401, invalidTokenHeader, "invalid_token")
		if !userExists(t, e, "apple", "apple-1") {
			t.Fatal("the user was deleted")
		}
	})

	r := deleteAccount(t, e, g.AccessToken)
	if r.Code != http.StatusNoContent || r.Body != "" {
		t.Fatalf("%d %q, want 204 and no body", r.Code, r.Body)
	}
	if userExists(t, e, "apple", "apple-1") {
		t.Error("the identity is still stored")
	}
	wantRevoked(t, e, app, live.RefreshToken)
	wantRevoked(t, e, app, g2.RefreshToken)
	revs := e.Mocks["apple"].Revocations()
	if len(revs) != 1 || revs[0].Token != stored {
		t.Errorf("revocations %+v, want one for the stored token", revs)
	}
	if !strings.Contains(e.Logs.String(), `"action":"user.delete"`) {
		t.Errorf("no audit line for the deletion in %s", e.Logs.String())
	}
	// The same token again: the user is gone.
	wantBearerError(t, deleteAccount(t, e, g.AccessToken), 401, invalidTokenHeader, "invalid_token")
	if len(e.Mocks["apple"].Revocations()) != 1 {
		t.Error("the second call revoked again")
	}
}

// Covers: FR-13, SEC-21
// Acceptance: Account deletion guard
func TestAccountDeleteGuard(t *testing.T) {
	e := server.New(t)
	t.Run("a client without allow_account_delete", func(t *testing.T) {
		g := e.Exchange(t, server.ClientQuery, e.Login(t, server.ClientQuery))
		wantBearerError(t, deleteAccount(t, e, g.AccessToken), 403, `Bearer error="insufficient_scope"`, "insufficient_scope")
		if !userExists(t, e, "google", "1001") {
			t.Error("the user was deleted")
		}
	})
	t.Run("a client removed from the realm", func(t *testing.T) {
		g := e.Exchange(t, server.ClientQuery, e.Login(t, server.ClientQuery))
		e.Reload(t, func(y string) string {
			return strings.Replace(y, "  web:\n", "  gone:\n", 1)
		})
		wantBearerError(t, deleteAccount(t, e, g.AccessToken), 403, `Bearer error="insufficient_scope"`, "insufficient_scope")
	})

	e = server.New(t)
	app := server.ClientDelete
	old := e.Exchange(t, app, e.Login(t, app))
	e.Clock.Advance(10 * time.Minute) // exactly the limit still counts
	// A login 10 minutes ago, with a token that lives 15 minutes.
	t.Run("a login exactly at the limit", func(t *testing.T) {
		probe := server.New(t)
		pg := probe.Exchange(t, app, probe.Login(t, app))
		probe.Clock.Advance(10 * time.Minute)
		if r := deleteAccount(t, probe, pg.AccessToken); r.Code != http.StatusNoContent {
			t.Errorf("%d %q, want 204", r.Code, r.Body)
		}
	})
	e.Clock.Advance(time.Second)
	header := `Bearer error="insufficient_user_authentication", max_age=600`
	wantBearerError(t, deleteAccount(t, e, old.AccessToken), 401, header, "insufficient_user_authentication")
	if !userExists(t, e, "google", "1001") {
		t.Fatal("the user was deleted")
	}
	// The app signs the user in again with prompt=login and retries.
	fresh := e.Exchange(t, app, e.Login(t, app, "prompt", "login"))
	if r := deleteAccount(t, e, fresh.AccessToken); r.Code != http.StatusNoContent {
		t.Fatalf("%d %q, want 204", r.Code, r.Body)
	}
	if userExists(t, e, "google", "1001") {
		t.Error("the user is still stored")
	}
}

// Covers: FR-13 (part), FR-09 (part), SEC-14 (part)
// Acceptance: Userinfo after deletion or disabling
func TestUserinfoAndDeleteAfterDeletionOrDisabling(t *testing.T) {
	app := server.ClientDelete
	t.Run("disabled", func(t *testing.T) {
		e := server.New(t)
		g := e.Exchange(t, app, e.Login(t, app))
		renameUser(t, e, "Ann Renamed")
		if got := claimsOf(t, userinfo(t, e, http.MethodGet, g.AccessToken, nil))["name"]; got != "Ann Renamed" {
			t.Errorf("name %v, want the stored one", got)
		}
		e.SetDisabled(t, true)
		wantBearerError(t, userinfo(t, e, http.MethodGet, g.AccessToken, nil), 401, invalidTokenHeader, "invalid_token")
		wantBearerError(t, deleteAccount(t, e, g.AccessToken), 401, invalidTokenHeader, "invalid_token")
		if !userExists(t, e, "google", "1001") {
			t.Error("a disabled user was deleted")
		}
	})
	t.Run("deleted", func(t *testing.T) {
		e := server.New(t)
		g := e.Exchange(t, app, e.Login(t, app))
		if r := deleteAccount(t, e, g.AccessToken); r.Code != 204 {
			t.Fatalf("%d", r.Code)
		}
		wantBearerError(t, userinfo(t, e, http.MethodGet, g.AccessToken, nil), 401, invalidTokenHeader, "invalid_token")
		wantBearerError(t, deleteAccount(t, e, g.AccessToken), 401, invalidTokenHeader, "invalid_token")
	})
}

// Covers: FR-13 (part), FR-21 (part), FR-58 (part)
// Acceptance: Wrong method (part)
func TestAccountDeleteWrongMethod(t *testing.T) {
	e := server.New(t)
	g := e.Exchange(t, server.ClientDelete, e.Login(t, server.ClientDelete))
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodOptions} {
		t.Run(m, func(t *testing.T) {
			r := deleteAccountWith(t, e, m, g.AccessToken)
			if r.Code != 405 || r.Header.Get("Allow") != "DELETE" || !strings.Contains(r.Body, `"invalid_request"`) {
				t.Errorf("%d %v %q", r.Code, r.Header, r.Body)
			}
		})
	}
	if !userExists(t, e, "google", "1001") {
		t.Error("the user was deleted")
	}
}

// Covers: FR-13 (part)
func TestAccountDeleteFaults(t *testing.T) {
	for _, row := range []struct {
		name   string
		fail   func(e *server.Env)
		status int
		code   string
	}{
		{"unavailable", func(e *server.Env) { e.Faults.Fail("Users.Delete", fmt.Errorf("%w: locked", store.ErrUnavailable)) }, 503, "temporarily_unavailable"},
		{"failing", func(e *server.Env) { e.Faults.Fail("Users.Delete", fmt.Errorf("disk on fire")) }, 500, "server_error"},
		{"deleted meanwhile", func(e *server.Env) { e.Faults.Fail("Users.Delete", store.ErrNotFound) }, 401, "invalid_token"},
		{"no realm", func(e *server.Env) { e.Faults.Fail("Realms.Find", store.ErrNotFound) }, 401, "invalid_token"},
	} {
		t.Run(row.name, func(t *testing.T) {
			e := server.New(t)
			g := e.Exchange(t, server.ClientDelete, e.Login(t, server.ClientDelete))
			row.fail(e)
			r := deleteAccount(t, e, g.AccessToken)
			if r.Code != row.status || !strings.Contains(r.Body, `"`+row.code+`"`) {
				t.Errorf("%d %q, want %d %s", r.Code, r.Body, row.status, row.code)
			}
			if row.status != 401 && r.Header.Get("WWW-Authenticate") != "" {
				t.Errorf("WWW-Authenticate %q on a store fault", r.Header.Get("WWW-Authenticate"))
			}
			e.Faults.Fail("Users.Delete", nil)
			e.Faults.Fail("Realms.Find", nil)
			if !userExists(t, e, "google", "1001") {
				t.Error("the user was deleted")
			}
		})
	}
}

// The checks run in the order of FR-13: the token, the client, the age of the
// login, then the user; a user that is gone or disabled is told last.
//
// Covers: FR-13 (part)
func TestAccountDeleteChecksTheUserLast(t *testing.T) {
	scope := `Bearer error="insufficient_scope"`
	reauth := `Bearer error="insufficient_user_authentication", max_age=600`
	for _, row := range []struct {
		name   string
		app    server.App
		age    time.Duration
		gone   func(t *testing.T, e *server.Env, access string)
		status int
		header string
		code   string
	}{
		{"disabled user, client not allowed", server.ClientQuery, 0, func(t *testing.T, e *server.Env, _ string) { e.SetDisabled(t, true) }, 403, scope, "insufficient_scope"},
		{"deleted user, client not allowed", server.ClientQuery, 0, deleteTheUser, 403, scope, "insufficient_scope"},
		{"disabled user, old login", server.ClientDelete, 11 * time.Minute, func(t *testing.T, e *server.Env, _ string) { e.SetDisabled(t, true) }, 401, reauth, "insufficient_user_authentication"},
		{"deleted user, old login", server.ClientDelete, 11 * time.Minute, deleteTheUser, 401, reauth, "insufficient_user_authentication"},
		{"disabled user, allowed and recent", server.ClientDelete, 0, func(t *testing.T, e *server.Env, _ string) { e.SetDisabled(t, true) }, 401, invalidTokenHeader, "invalid_token"},
	} {
		t.Run(row.name, func(t *testing.T) {
			e := server.New(t)
			g := e.Exchange(t, row.app, e.Login(t, row.app))
			row.gone(t, e, g.AccessToken)
			e.Clock.Advance(row.age)
			wantBearerError(t, deleteAccount(t, e, g.AccessToken), row.status, row.header, row.code)
		})
	}
}

// deleteTheUser deletes the user of the token through a client that may.
func deleteTheUser(t *testing.T, e *server.Env, _ string) {
	t.Helper()
	g := e.Exchange(t, server.ClientDelete, e.Login(t, server.ClientDelete))
	if r := deleteAccount(t, e, g.AccessToken); r.Code != http.StatusNoContent {
		t.Fatalf("%d %q", r.Code, r.Body)
	}
}
