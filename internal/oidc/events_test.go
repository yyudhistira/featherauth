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

const eventsURL = server.Issuer + "/events/apple"

var jsonHeader = http.Header{"Content-Type": {"application/json"}}

func postEvent(t *testing.T, e *server.Env, body string) server.Response {
	t.Helper()
	return e.NewClient().Request(t, http.MethodPost, eventsURL, body, jsonHeader)
}

// appleEvent is the body Apple posts for the event, signed by the mock.
func appleEvent(e *server.Env, typ, sub string) string {
	return e.Mocks["apple"].SignedEvent(e.Mocks["apple"].ClientID(), typ, sub)
}

// appleLogin signs a user in through Apple and returns the grant.
func appleLoginGrant(t *testing.T, e *server.Env, sub, email string) (server.App, string) {
	t.Helper()
	app := server.ClientDelete
	e.Mocks["apple"].SetUser(mockidp.User{Sub: sub, Name: "Ann Lee", Email: email, EmailVerified: true})
	g := e.Exchange(t, app, e.NewClient().Login(t, server.Authorize(app, "apple")))
	return app, g.RefreshToken
}

// identity returns the stored identity of the provider subject.
func identityOf(t *testing.T, e *server.Env, prov config.ProviderKey, sub string) (store.Identity, error) {
	t.Helper()
	ctx := context.Background()
	var id store.Identity
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		id, err = tx.Identities().Find(ctx, rid, prov, sub)
		return err
	})
	return id, err
}

func auditActions(t *testing.T, e *server.Env) []store.AuditEvent {
	t.Helper()
	ctx := context.Background()
	var rows []store.AuditEvent
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		all, err := tx.Audit().List(ctx, rid, e.Clock.Now().Add(-24*time.Hour))
		for _, a := range all {
			if strings.HasPrefix(a.Actor, "provider:") && a.Action != "identity.auto_link" {
				rows = append(rows, a)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func wantOK(t *testing.T, r server.Response) {
	t.Helper()
	if r.Code != http.StatusOK {
		t.Fatalf("status %d %q, want 200", r.Code, r.Body)
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleEventConsentRevoked(t *testing.T) {
	e := server.New(t)
	app, rt := appleLoginGrant(t, e, "apple-1", "ann@example.com")
	if id, err := identityOf(t, e, "apple", "apple-1"); err != nil || id.ProviderRefreshTokenEnc == "" {
		t.Fatalf("the login stored no Apple token: %v", err)
	}
	wantOK(t, postEvent(t, e, appleEvent(e, "consent-revoked", "apple-1")))

	wantRevoked(t, e, app, rt)
	id, err := identityOf(t, e, "apple", "apple-1")
	if err != nil {
		t.Fatalf("the user was deleted: %v", err)
	}
	if id.ProviderRefreshTokenEnc != "" {
		t.Error("the Apple token is kept")
	}
	if n := len(e.Mocks["apple"].Revocations()); n != 0 {
		t.Errorf("%d revocations at Apple, want none", n)
	}
	rows := auditActions(t, e)
	if len(rows) != 1 || rows[0].Action != "identity.consent_revoked" || rows[0].Actor != "provider:apple" {
		t.Fatalf("audit = %+v", rows)
	}
	if !strings.Contains(e.Logs.String(), `"action":"identity.consent_revoked"`) {
		t.Errorf("no audit line in %s", e.Logs.String())
	}

	t.Run("a later login returns to the same account", func(t *testing.T) {
		g := e.Exchange(t, app, e.NewClient().Login(t, server.Authorize(app, "apple")))
		if g.RefreshToken == "" {
			t.Fatal("no refresh token")
		}
		if got, _ := identityOf(t, e, "apple", "apple-1"); got.UserID != id.UserID {
			t.Errorf("the login went to another user")
		}
	})
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleEventAccountDeleteOfAnAppleOnlyUser(t *testing.T) {
	e := server.New(t)
	app, rt := appleLoginGrant(t, e, "apple-1", "ann@example.com")
	wantOK(t, postEvent(t, e, appleEvent(e, "account-delete", "apple-1")))

	if _, err := identityOf(t, e, "apple", "apple-1"); err == nil {
		t.Fatal("the user is still there")
	}
	wantRevoked(t, e, app, rt)
	if n := len(e.Mocks["apple"].Revocations()); n != 0 {
		t.Errorf("%d revocations at Apple, want none (the account is gone at Apple)", n)
	}
	rows := auditActions(t, e)
	if len(rows) != 1 || rows[0].Action != "user.delete" || rows[0].Actor != "provider:apple" {
		t.Fatalf("audit = %+v", rows)
	}

	t.Run("the same event again", func(t *testing.T) {
		wantOK(t, postEvent(t, e, appleEvent(e, "account-delete", "apple-1")))
		if n := len(auditActions(t, e)); n != 1 {
			t.Errorf("%d audit rows after the repeat, want 1", n)
		}
	})
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleEventAccountDeleteOfAUserWithGoogle(t *testing.T) {
	e := server.New(t)
	app, rt := appleLoginGrant(t, e, "apple-1", "ann@example.com")
	ctx := context.Background()
	apple, _ := identityOf(t, e, "apple", "apple-1")
	err := e.Store.Write(ctx, func(tx store.Tx) error {
		return tx.Identities().Create(ctx, store.Identity{
			ID: "g-ident", RealmID: apple.RealmID, UserID: apple.UserID, Provider: "google", ProviderSub: "g-1", CreatedAt: e.Clock.Now(),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	wantOK(t, postEvent(t, e, appleEvent(e, "account-delete", "apple-1")))

	if _, err := identityOf(t, e, "apple", "apple-1"); err == nil {
		t.Error("the Apple identity is still linked")
	}
	if g, err := identityOf(t, e, "google", "g-1"); err != nil || g.UserID != apple.UserID {
		t.Errorf("the Google identity: %+v %v", g, err)
	}
	wantRevoked(t, e, app, rt)
	rows := auditActions(t, e)
	if len(rows) != 1 || rows[0].Action != "identity.unlink" || rows[0].Actor != "provider:apple" {
		t.Fatalf("audit = %+v", rows)
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleEventEmailChangesAreOnlyLogged(t *testing.T) {
	e := server.New(t)
	app, rt := appleLoginGrant(t, e, "apple-1", "ann@example.com")
	for _, typ := range []string{"email-disabled", "email-enabled"} {
		wantOK(t, postEvent(t, e, appleEvent(e, typ, "apple-1")))
	}
	if n := len(auditActions(t, e)); n != 0 {
		t.Errorf("%d audit rows, want none", n)
	}
	if id, err := identityOf(t, e, "apple", "apple-1"); err != nil || id.ProviderRefreshTokenEnc == "" {
		t.Errorf("the identity changed: %+v %v", id, err)
	}
	wantAlive(t, e, app, rt)
	if !strings.Contains(e.Logs.String(), "email-disabled") || !strings.Contains(e.Logs.String(), "email-enabled") {
		t.Errorf("the events are not logged: %s", e.Logs.String())
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleEventRepeatChangesNothing(t *testing.T) {
	e := server.New(t)
	app, rt := appleLoginGrant(t, e, "apple-1", "ann@example.com")
	body := appleEvent(e, "consent-revoked", "apple-1")
	wantOK(t, postEvent(t, e, body))
	first, _ := identityOf(t, e, "apple", "apple-1")
	wantOK(t, postEvent(t, e, body))
	second, _ := identityOf(t, e, "apple", "apple-1")
	if first != second {
		t.Errorf("the repeat changed the identity: %+v -> %+v", first, second)
	}
	wantRevoked(t, e, app, rt)
	rows := auditActions(t, e)
	if len(rows) != 1 {
		t.Fatalf("%d audit rows after the repeat, want 1: %+v", len(rows), rows)
	}
	// A second notification has its own jti, so it is acted on and audited again.
	wantOK(t, postEvent(t, e, appleEvent(e, "consent-revoked", "apple-1")))
	rows = auditActions(t, e)
	if len(rows) != 2 {
		t.Fatalf("%d audit rows after a second notification, want 2: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if r.Action != "identity.consent_revoked" {
			t.Errorf("audit action %q, want identity.consent_revoked", r.Action)
		}
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleEventUnknownSubjectAndType(t *testing.T) {
	e := server.New(t)
	app, rt := appleLoginGrant(t, e, "apple-1", "ann@example.com")
	for _, c := range []struct{ typ, sub, logged string }{
		{"consent-revoked", "nobody", "unknown subject"},
		{"account-delete", "nobody", "unknown subject"},
		{"something-new", "apple-1", "unknown type"},
	} {
		t.Run(c.typ+" "+c.sub, func(t *testing.T) {
			e.Logs.Reset()
			wantOK(t, postEvent(t, e, appleEvent(e, c.typ, c.sub)))
			if !strings.Contains(e.Logs.String(), c.logged) {
				t.Errorf("%q is not logged: %s", c.logged, e.Logs.String())
			}
		})
	}
	if n := len(auditActions(t, e)); n != 0 {
		t.Errorf("%d audit rows, want none", n)
	}
	wantAlive(t, e, app, rt)
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleEventVerificationFailures(t *testing.T) {
	e := server.New(t)
	app, rt := appleLoginGrant(t, e, "apple-1", "ann@example.com")
	mock := e.Mocks["apple"]
	valid := appleEvent(e, "account-delete", "apple-1")
	altered := valid[:len(valid)-6] + "AAAA\"}"
	cases := []struct{ name, body string }{
		{"a bad signature", altered},
		{"a wrong aud", mock.SignedEvent("com.example.other", "account-delete", "apple-1")},
		{"not JSON", "not json"},
		{"no payload", "{}"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := postEvent(t, e, c.body)
			if r.Code != http.StatusBadRequest {
				t.Fatalf("status %d %q, want 400", r.Code, r.Body)
			}
		})
	}
	if _, err := identityOf(t, e, "apple", "apple-1"); err != nil {
		t.Fatal("a rejected event changed the user")
	}
	wantAlive(t, e, app, rt)
	if n := len(auditActions(t, e)); n != 0 {
		t.Errorf("%d audit rows, want none", n)
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events (part)
func TestAppleEventNotificationAudience(t *testing.T) {
	e := server.New(t)
	appleLoginGrant(t, e, "apple-1", "ann@example.com")
	// The test adapter lists com.example.app in notification_audiences.
	wantOK(t, postEvent(t, e, e.Mocks["apple"].SignedEvent("com.example.app", "consent-revoked", "apple-1")))
	if n := len(auditActions(t, e)); n != 1 {
		t.Errorf("%d audit rows, want 1", n)
	}
}

// Covers: FR-31
// Acceptance: Apple events (part)
func TestAppleEventEndpointRefusals(t *testing.T) {
	e := server.New(t)
	body := appleEvent(e, "consent-revoked", "apple-1")
	t.Run("GET", func(t *testing.T) {
		r := e.NewClient().Request(t, http.MethodGet, eventsURL, "", nil)
		if r.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status %d, want 405", r.Code)
		}
	})
	t.Run("a provider without events", func(t *testing.T) {
		r := e.NewClient().Request(t, http.MethodPost, server.Issuer+"/events/github", body, jsonHeader)
		if r.Code != http.StatusNotFound {
			t.Fatalf("status %d, want 404", r.Code)
		}
	})
}

// Covers: FR-31
// Acceptance: Apple events (part)
func TestAppleEventStoreFailureIsRetried(t *testing.T) {
	e := server.New(t)
	appleLoginGrant(t, e, "apple-1", "ann@example.com")
	e.Faults.Fail("Users.Delete", fmt.Errorf("disk on fire"))
	r := postEvent(t, e, appleEvent(e, "account-delete", "apple-1"))
	if r.Code != http.StatusInternalServerError || !strings.Contains(r.Body, `"server_error"`) {
		t.Fatalf("status %d %q, want 500 server_error", r.Code, r.Body)
	}
	if _, err := identityOf(t, e, "apple", "apple-1"); err != nil {
		t.Error("the failed event changed the user")
	}
}

// Covers: FR-31, SEC-22
// Acceptance: Apple events
func TestAppleEventsAcceptance(t *testing.T) {
	e := server.New(t)
	app, rt1 := appleLoginGrant(t, e, "apple-1", "ann@example.com") // consent-revoked
	_, rt2 := appleLoginGrant(t, e, "apple-2", "bob@example.com")   // Apple only, account-delete
	app3, rt3 := appleLoginGrant(t, e, "apple-3", "cy@example.com") // Apple and Google, account-delete
	ctx := context.Background()
	three, _ := identityOf(t, e, "apple", "apple-3")
	err := e.Store.Write(ctx, func(tx store.Tx) error {
		return tx.Identities().Create(ctx, store.Identity{
			ID: "g3", RealmID: three.RealmID, UserID: three.UserID, Provider: "google", ProviderSub: "g-3", CreatedAt: e.Clock.Now(),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	mock := e.Mocks["apple"]
	altered := appleEvent(e, "consent-revoked", "apple-1")
	altered = altered[:len(altered)-6] + "AAAA\"}"

	steps := []struct {
		name, body string
		status     int
		audits     int // provider audit rows after the step
	}{
		{"consent-revoked", appleEvent(e, "consent-revoked", "apple-1"), 200, 1},
		{"account-delete, Apple only", appleEvent(e, "account-delete", "apple-2"), 200, 2},
		{"account-delete, with Google", appleEvent(e, "account-delete", "apple-3"), 200, 3},
		{"email-disabled", appleEvent(e, "email-disabled", "apple-1"), 200, 3},
		{"the same event twice", appleEvent(e, "account-delete", "apple-2"), 200, 3},
		{"a bad signature", altered, 400, 3},
		{"a wrong aud", mock.SignedEvent("com.example.other", "account-delete", "apple-1"), 400, 3},
		{"an unknown sub", appleEvent(e, "account-delete", "nobody"), 200, 3},
	}
	for _, s := range steps {
		if r := postEvent(t, e, s.body); r.Code != s.status {
			t.Fatalf("%s: status %d %q, want %d", s.name, r.Code, r.Body, s.status)
		}
		if n := len(auditActions(t, e)); n != s.audits {
			t.Fatalf("%s: %d audit rows, want %d", s.name, n, s.audits)
		}
	}

	if id, err := identityOf(t, e, "apple", "apple-1"); err != nil || id.ProviderRefreshTokenEnc != "" {
		t.Errorf("consent-revoked: identity %+v, %v; want the user kept and the token dropped", id, err)
	}
	wantRevoked(t, e, app, rt1)
	if _, err := identityOf(t, e, "apple", "apple-2"); err == nil {
		t.Error("the Apple-only user was not deleted")
	}
	wantRevoked(t, e, app, rt2)
	if _, err := identityOf(t, e, "apple", "apple-3"); err == nil {
		t.Error("the Apple identity of the Google user was not unlinked")
	}
	if g, err := identityOf(t, e, "google", "g-3"); err != nil || g.UserID != three.UserID {
		t.Errorf("the Google identity: %+v %v", g, err)
	}
	wantRevoked(t, e, app3, rt3)
	for _, a := range auditActions(t, e) {
		if a.Actor != "provider:apple" || a.UserID == "" {
			t.Errorf("audit row %+v", a)
		}
	}
}
