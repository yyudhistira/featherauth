package oidc_test

import (
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// Covers: FR-31 (part), FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// Apple's signed consent-revoked event, posted to the events endpoint, ends the
// browser session of the user who holds the identity: the request is answered and
// the next authorization request goes to the provider.
func appleConsentRevokedEnds(t *testing.T) {
	e := server.New(t)
	ssoOn(t, e)
	e.Mocks["apple"].SetUser(mockidp.User{Sub: "apple-1", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
	c := e.NewClient()
	c.Login(t, server.Authorize(server.ClientDelete, "apple"))
	cookie := browserCookie(c)
	if cookie == "" {
		t.Fatal("the Apple login set no browser session cookie")
	}
	wantOK(t, postEvent(t, e, appleEvent(e, "consent-revoked", "apple-1")))
	if _, ok := browserRow(t, e, cookie); ok {
		t.Fatal("the browser session survived Apple's consent-revoked event")
	}
	wantNextToProvider(t, e, c, "apple")
}

// Covers: FR-31 (part), FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// Apple's signed account-delete event for an Apple-only user deletes the user, and
// with the user its browser session.
func appleAccountDeleteEnds(t *testing.T) {
	e := server.New(t)
	ssoOn(t, e)
	e.Mocks["apple"].SetUser(mockidp.User{Sub: "apple-1", Name: "Ann Lee", Email: "ann@example.com", EmailVerified: true})
	c := e.NewClient()
	c.Login(t, server.Authorize(server.ClientDelete, "apple"))
	cookie := browserCookie(c)
	wantOK(t, postEvent(t, e, appleEvent(e, "account-delete", "apple-1")))
	if _, ok := browserRow(t, e, cookie); ok {
		t.Fatal("the browser session survived Apple's account-delete event")
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on end (part)
// Meta's signed data-deletion callback for a Facebook-only user deletes the user and
// its browser session, end to end through the callback endpoint.
func metaDeletionEnds(t *testing.T) {
	e := server.New(t)
	ssoOn(t, e)
	e.Mocks["facebook"].SetUser(mockidp.User{Sub: "fb-1", Name: "Ann Lee", Email: "ann@example.com"})
	c := e.NewClient()
	c.Login(t, server.Authorize(server.ClientDelete, "facebook"))
	cookie := browserCookie(c)
	if cookie == "" {
		t.Fatal("the Facebook login set no browser session cookie")
	}
	wantMetaAnswer(t, metaRequest(t, e, metaSigned(e, "fb-1", e.Clock.Now(), nil)))
	if _, ok := browserRow(t, e, cookie); ok {
		t.Fatal("the browser session survived Meta's deletion callback")
	}
}

// wantNextToProvider checks that the next authorization request of the browser
// goes to the provider key, which it does once the browser session has ended.
func wantNextToProvider(t *testing.T, e *server.Env, c *server.Client, key string) {
	t.Helper()
	before := contacts(e, key)
	c.Login(t, server.Authorize(server.ClientFragment, key))
	if contacts(e, key) != before+1 {
		t.Fatalf("the next authorization request did not go to %s", key)
	}
}
