package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
	"github.com/yyudhistira/featherauth/internal/web"
)

// p30AuditRows counts the identity.sessions_revoked rows of the provider google.
func p30AuditRows(t *testing.T, e *server.Env) int {
	t.Helper()
	n := 0
	err := e.Store.Read(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(context.Background(), "main")
		if err != nil {
			return err
		}
		rows, err := tx.Audit().List(context.Background(), rid, e.Clock.Now().Add(-24*time.Hour))
		for _, a := range rows {
			if a.Action == "identity.sessions_revoked" && a.Actor == "provider:google" && a.Details["event"] == "sessions-revoked" {
				n++
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// p30English fails when a page still holds English text of the built-in messages.
func p30English(t *testing.T, name, body string) {
	t.Helper()
	for mid, english := range web.English {
		if strings.Contains(body, english) {
			t.Errorf("the %s page still holds the English text of %s: %q", name, mid, english)
		}
	}
}

// p30Get fetches a page of the service as a browser that asks for Indonesian.
func p30Get(t *testing.T, e *server.Env, rawURL string) server.Response {
	t.Helper()
	return e.NewClient().Request(t, http.MethodGet, rawURL, "", http.Header{"Accept-Language": {"id"}})
}

// p30Cookie returns the browser session cookie of the client, or "".
func p30Cookie(c *server.Client) string {
	for _, ck := range c.Cookies() {
		if ck.Name == "fa_sso_main" {
			return ck.Value
		}
	}
	return ""
}

// p30BrowserSession reports whether the browser session of the cookie is stored.
func p30BrowserSession(t *testing.T, e *server.Env, value string) bool {
	t.Helper()
	found := false
	err := e.Store.Read(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(context.Background(), "main")
		if err != nil {
			return err
		}
		_, err = tx.SSOSessions().Find(context.Background(), rid, secure.HashOf(value))
		found = err == nil
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// p30Identity reports whether the realm still has the identity.
func p30Identity(t *testing.T, e *server.Env, prov config.ProviderKey, sub string) bool {
	t.Helper()
	found := false
	err := e.Store.Read(context.Background(), func(tx store.Tx) error {
		rid, err := tx.Realms().Find(context.Background(), "main")
		if err != nil {
			return err
		}
		_, err = tx.Identities().Find(context.Background(), rid, prov, sub)
		found = err == nil
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// Covers: FR-50, FR-48, FR-45, SEC-39 (part)
// Acceptance: Built-in languages (part)
// Acceptance: Google security events (part)
// The real service, with id listed and single sign-on on: the pages are in
// Indonesian, and a Google login whose refresh token and browser session a Google
// security event ends (sessions-revoked): the identity stays, the event's audit row
// is written, and the next authorization goes to Google again.
func TestPhase30Wiring(t *testing.T) {
	e := server.New(t)
	e.Reload(t, func(y string) string {
		y = strings.Replace(y, "login_page:\n  contact: help@example.com\n", "login_page:\n  contact: help@example.com\n  supported_locales: [en, id]\n", 1)
		return strings.Replace(y, "name: main\n", "name: main\nsso:\n  enabled: true\n", 1)
	})

	// The pages, in Indonesian: the chooser, an error page and the data-deletion page.
	chooser := p30Get(t, e, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(server.ClientDelete, "").Encode())
	if chooser.Code != http.StatusOK || !strings.Contains(chooser.Body, `lang="id"`) || !strings.Contains(chooser.Body, "Masuk dengan Google") {
		t.Errorf("the chooser is not in Indonesian: status %d\n%s", chooser.Code, chooser.Body)
	}
	p30English(t, "chooser", chooser.Body)
	bad := p30Get(t, e, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?client_id=unknown-client")
	if !strings.Contains(bad.Body, `lang="id"`) {
		t.Errorf("the error page is not in Indonesian:\n%s", bad.Body)
	}
	p30English(t, "error", bad.Body)
	deletion := p30Get(t, e, e.Realm.EndpointURL(config.EndpointDataDeletion, ""))
	if deletion.Code != http.StatusOK || !strings.Contains(deletion.Body, `lang="id"`) {
		t.Errorf("the data-deletion page is not in Indonesian: status %d\n%s", deletion.Code, deletion.Body)
	}
	p30English(t, "data-deletion", deletion.Body)

	// A Google login: the refresh token, the browser session and the identity.
	app := server.ClientDelete
	e.Mocks["google"].SetUser(mockidp.User{Sub: "g-p30", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
	c := e.NewClient()
	g := e.Exchange(t, app, c.Login(t, server.Authorize(app, "google")))
	cookie := p30Cookie(c)
	if cookie == "" || !p30BrowserSession(t, e, cookie) {
		t.Fatal("the Google login set no browser session")
	}

	// Google's security event: sessions-revoked for that account.
	gm := e.Mocks["google"]
	token := gm.SecurityEvent(gm.ClientID(), map[string]any{
		"https://schemas.openid.net/secevent/risc/event-type/sessions-revoked": map[string]any{
			"subject": map[string]any{"subject_type": "iss-sub", "iss": mockidp.RISCIssuer, "sub": "g-p30"},
		},
	})
	if r := e.NewClient().Request(t, http.MethodPost, server.Issuer+"/events/google", token, http.Header{"Content-Type": {"application/secevent+jwt"}}); r.Code != http.StatusAccepted {
		t.Fatalf("the event: status %d %s", r.Code, r.Body)
	}
	if rt := e.NewClient().PostToken(t, server.RefreshForm(app, g.RefreshToken), nil); rt.Code == http.StatusOK {
		t.Error("the refresh token survived sessions-revoked")
	}
	if p30BrowserSession(t, e, cookie) {
		t.Error("the browser session survived sessions-revoked")
	}
	if n := p30AuditRows(t, e); n != 1 {
		t.Errorf("%d identity.sessions_revoked rows for the event, want 1", n)
	}
	if !p30Identity(t, e, "google", "g-p30") {
		t.Error("the Google identity was removed")
	}
	// The next authorization goes to Google again.
	next := e.NewClient().Request(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointAuthorize, "")+"?"+server.Authorize(app, "google").Encode(), "", nil)
	if !strings.HasPrefix(next.Header.Get("Location"), e.Mocks["google"].URL()) {
		t.Errorf("the next authorization does not reach Google: %q", next.Header.Get("Location"))
	}
}
