package token_test

import (
	"context"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/token"
)

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
// A login code carries the hash of the browser session it started into the token
// session, and the rotated successors of that session keep it; a login that
// started no browser session keeps none, also after a rotation.
func TestSSOIDHashTravelsFromTheCodeToTheSuccessors(t *testing.T) {
	e := newRefreshEnv(t)
	ctx := context.Background()
	ssoHash := secure.HashOf("browser-cookie-value")
	code, err := e.codes.Issue(ctx, token.IssueInput{
		Realm: e.realm, Client: e.client("web"), User: "u1", RedirectURI: cb,
		CodeChallenge: s256(verifier), Nonce: "n-1", AuthTime: e.clock.Now().Add(-time.Minute),
		SSOIDHash: ssoHash,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	g, err := e.codes.Exchange(ctx, e.in("web", code, cb, verifier))
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if rt := e.refreshRow(t, g.RefreshToken); rt.SSOIDHash != ssoHash {
		t.Fatalf("the token session's SSOIDHash = %q, want the login's hash %q", rt.SSOIDHash, ssoHash)
	}
	next := e.mustRefresh(t, "web", g.RefreshToken)
	if rt := e.refreshRow(t, next.RefreshToken); rt.SSOIDHash != ssoHash {
		t.Fatalf("the successor's SSOIDHash = %q, want %q", rt.SSOIDHash, ssoHash)
	}

	plain := e.login(t, "web")
	if rt := e.refreshRow(t, plain.RefreshToken); rt.SSOIDHash != "" {
		t.Fatalf("a login without a browser session has SSOIDHash %q", rt.SSOIDHash)
	}
	plainNext := e.mustRefresh(t, "web", plain.RefreshToken)
	if rt := e.refreshRow(t, plainNext.RefreshToken); rt.SSOIDHash != "" {
		t.Fatalf("the successor of a session without a browser session has SSOIDHash %q", rt.SSOIDHash)
	}
}
