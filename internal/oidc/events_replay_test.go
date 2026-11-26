package oidc_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// appleClaims are the claims of an Apple notification that a test then changes:
// a payload with an exp an hour from now, an iat of the same time, a jti and
// the events claim.
func appleClaims(e *server.Env, jti string, events any) map[string]any {
	now := e.Clock.Now()
	return map[string]any{
		"iss": provider.AppleIssuer, "aud": e.Mocks["apple"].ClientID(),
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "jti": jti, "events": events,
	}
}

// signedBody is the body Apple posts for claims, signed by the mock.
func signedBody(e *server.Env, claims map[string]any) string {
	return e.Mocks["apple"].SignedClaims(claims)
}

// rememberedFirst reports whether the id of a provider event is new to the
// store, and remembers it when it is.
func rememberedFirst(t *testing.T, e *server.Env, jti string, exp time.Time) bool {
	t.Helper()
	ctx := context.Background()
	var first bool
	err := e.Store.Write(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		first, err = tx.ProviderEvents().Remember(ctx, rid, "apple", secure.HashOf(jti), exp)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return first
}

// Covers: SEC-27, FR-31
// Acceptance: Event replay
func TestEventReplayAcceptance(t *testing.T) {
	e := server.New(t)
	mock := e.Mocks["apple"]

	t.Run("account-delete, then a new user with the same Apple id gets the same payload", func(t *testing.T) {
		app, rt := appleLoginGrant(t, e, "apple-1", "ann@example.com")
		body := appleEvent(e, "account-delete", "apple-1")
		wantOK(t, postEvent(t, e, body))
		if _, err := identityOf(t, e, "apple", "apple-1"); err == nil {
			t.Fatal("the user is still there")
		}
		wantRevoked(t, e, app, rt)

		_, rt2 := appleLoginGrant(t, e, "apple-1", "ann@example.com")
		rows := len(auditActions(t, e))
		e.Logs.Reset()
		wantOK(t, postEvent(t, e, body))
		if id, err := identityOf(t, e, "apple", "apple-1"); err != nil || id.ProviderRefreshTokenEnc == "" {
			t.Errorf("the new user was deleted by the repeat: %v", err)
		}
		if n := len(auditActions(t, e)); n != rows {
			t.Errorf("the repeat wrote %d audit rows", n-rows)
		}
		wantAlive(t, e, app, rt2)
		if !strings.Contains(e.Logs.String(), "already acted on") {
			t.Errorf("the repeat is not logged: %s", e.Logs.String())
		}
	})

	t.Run("a payload whose action fails in the store is acted on at the retry", func(t *testing.T) {
		appleLoginGrant(t, e, "apple-2", "bob@example.com")
		body := appleEvent(e, "account-delete", "apple-2")
		rows := len(auditActions(t, e))
		e.Faults.Fail("Users.Delete", fmt.Errorf("disk on fire"))
		r := postEvent(t, e, body)
		if r.Code != http.StatusInternalServerError || !strings.Contains(r.Body, `"server_error"`) {
			t.Fatalf("status %d %q, want 500", r.Code, r.Body)
		}
		if _, err := identityOf(t, e, "apple", "apple-2"); err != nil {
			t.Fatal("the failed action changed the user")
		}
		if n := len(auditActions(t, e)); n != rows {
			t.Fatalf("the failed action wrote %d audit rows", n-rows)
		}
		e.Faults.Fail("Users.Delete", nil)
		wantOK(t, postEvent(t, e, body))
		if _, err := identityOf(t, e, "apple", "apple-2"); err == nil {
			t.Fatal("the retry was not acted on")
		}
		if n := len(auditActions(t, e)); n != rows+1 {
			t.Fatalf("the retry wrote %d audit rows, want 1", n-rows)
		}
	})

	t.Run("a payload without jti is acted on the first time only", func(t *testing.T) {
		app, rt := appleLoginGrant(t, e, "apple-3", "cy@example.com")
		claims := appleClaims(e, "", `{"type":"consent-revoked","sub":"apple-3"}`)
		delete(claims, "jti")
		body := signedBody(e, claims)
		rows := len(auditActions(t, e))
		wantOK(t, postEvent(t, e, body))
		if n := len(auditActions(t, e)); n != rows+1 {
			t.Fatalf("the first post wrote %d audit rows, want 1", n-rows)
		}
		wantOK(t, postEvent(t, e, body))
		if n := len(auditActions(t, e)); n != rows+1 {
			t.Fatalf("the repeat wrote %d audit rows, want 1", n-rows)
		}
		wantRevoked(t, e, app, rt)
	})

	t.Run("keys that cannot be fetched get 503 until they can", func(t *testing.T) {
		app, rt := appleLoginGrant(t, e, "apple-4", "dee@example.com")
		mock.RotateKey() // the event is signed with a key the service has not fetched
		mock.FailJWKS(100)
		t.Cleanup(func() { mock.FailJWKS(0) }) // a failed check must not leave the key endpoint down for later tests
		body := mock.SignedEvent(mock.ClientID(), "consent-revoked", "apple-4")
		rows := len(auditActions(t, e))
		r := postEvent(t, e, body)
		if r.Code != http.StatusServiceUnavailable || !strings.Contains(r.Body, `"temporarily_unavailable"`) {
			t.Fatalf("status %d %q, want 503 temporarily_unavailable", r.Code, r.Body)
		}
		if n := len(auditActions(t, e)); n != rows {
			t.Fatalf("the refused post wrote %d audit rows", n-rows)
		}
		wantAlive(t, e, app, rt)
		mock.FailJWKS(0)
		wantOK(t, postEvent(t, e, body))
		if n := len(auditActions(t, e)); n != rows+1 {
			t.Fatalf("the retry wrote %d audit rows, want 1", n-rows)
		}
		wantRevoked(t, e, app, rt)
	})

	t.Run("the hourly job removes a remembered id after its exp", func(t *testing.T) {
		claims := appleClaims(e, "job-1", `{"type":"consent-revoked","sub":"nobody"}`)
		exp := e.Clock.Now().Add(time.Hour)
		wantOK(t, postEvent(t, e, signedBody(e, claims)))
		if rememberedFirst(t, e, "job-1", exp) {
			t.Fatal("the id is not remembered after the post")
		}
		e.Clock.Advance(2 * time.Hour)
		if _, err := store.Cleanup(context.Background(), e.Store, e.Clock.Now()); err != nil {
			t.Fatal(err)
		}
		if !rememberedFirst(t, e, "job-1", exp.Add(time.Hour)) {
			t.Fatal("the id is still remembered after the job")
		}
	})

	t.Run("the same consent-revoked payload twice, then a second notification", func(t *testing.T) {
		app, rt := appleLoginGrant(t, e, "apple-5", "eve@example.com")
		body := appleEvent(e, "consent-revoked", "apple-5")
		rows := len(auditActions(t, e))
		wantOK(t, postEvent(t, e, body))
		wantOK(t, postEvent(t, e, body))
		if n := len(auditActions(t, e)); n != rows+1 {
			t.Fatalf("the payload twice wrote %d audit rows, want 1", n-rows)
		}
		wantOK(t, postEvent(t, e, appleEvent(e, "consent-revoked", "apple-5")))
		if n := len(auditActions(t, e)); n != rows+2 {
			t.Fatalf("a second notification wrote %d audit rows, want 2", n-rows)
		}
		wantRevoked(t, e, app, rt)
	})
}

// Covers: FR-31, SEC-22
// Acceptance: Apple event formats
func TestAppleEventFormatsAcceptance(t *testing.T) {
	e := server.New(t)
	now := e.Clock.Now()
	// Both forms of the events claim and both names of the deletion are acted on alike.
	for _, c := range []struct {
		name, sub string
		events    any
	}{
		{"object, account-deleted", "fmt-1", map[string]any{"type": "account-deleted", "sub": "fmt-1"}},
		{"object, account-delete", "fmt-2", map[string]any{"type": "account-delete", "sub": "fmt-2"}},
		{"string, account-deleted", "fmt-3", `{"type":"account-deleted","sub":"fmt-3"}`},
		{"string, account-delete", "fmt-4", `{"type":"account-delete","sub":"fmt-4"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			appleLoginGrant(t, e, c.sub, c.sub+"@example.com")
			claims := appleClaims(e, "format-"+c.sub, c.events)
			wantOK(t, postEvent(t, e, signedBody(e, claims)))
			if _, err := identityOf(t, e, "apple", c.sub); err == nil {
				t.Fatal("the user is still there")
			}
		})
	}
	for _, c := range []struct {
		name   string
		mod    func(map[string]any)
		status int
	}{
		{"no exp, issued an hour ago", func(c map[string]any) {
			delete(c, "exp")
			c["iat"] = now.Add(-time.Hour).Unix()
		}, http.StatusOK},
		{"no exp, issued 25 hours ago", func(c map[string]any) {
			delete(c, "exp")
			c["iat"] = now.Add(-25 * time.Hour).Unix()
		}, http.StatusBadRequest},
		{"no exp, issued 6 minutes ahead", func(c map[string]any) {
			delete(c, "exp")
			c["iat"] = now.Add(6 * time.Minute).Unix()
		}, http.StatusBadRequest},
		{"exp in the past", func(c map[string]any) {
			c["exp"] = now.Add(-time.Second).Unix()
		}, http.StatusBadRequest},
	} {
		t.Run(c.name, func(t *testing.T) {
			appleLoginGrant(t, e, "fmt-5", "f5@example.com")
			claims := appleClaims(e, "", `{"type":"account-delete","sub":"fmt-5"}`)
			claims["jti"] = "fmt-5-" + strings.ReplaceAll(c.name, " ", "-")
			c.mod(claims)
			rows := len(auditActions(t, e))
			r := postEvent(t, e, signedBody(e, claims))
			if r.Code != c.status {
				t.Fatalf("status %d %q, want %d", r.Code, r.Body, c.status)
			}
			if c.status == http.StatusOK {
				if _, err := identityOf(t, e, "apple", "fmt-5"); err == nil {
					t.Fatal("the accepted payload was not acted on")
				}
				return
			}
			if _, err := identityOf(t, e, "apple", "fmt-5"); err != nil {
				t.Fatal("the refused payload changed the user")
			}
			if n := len(auditActions(t, e)); n != rows {
				t.Fatalf("the refused payload wrote %d audit rows", n-rows)
			}
		})
	}
}
