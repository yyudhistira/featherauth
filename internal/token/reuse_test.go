package token_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/token"
)

// reuseOf returns the reuse a refusal carries, failing when it has none.
func reuseOf(t *testing.T, err error) token.Reuse {
	t.Helper()
	var ge *token.GrantError
	if !errors.As(err, &ge) || ge.Code != token.CodeInvalidGrant || ge.Reuse == nil {
		t.Fatalf("err = %v, want an invalid_grant carrying a reuse", err)
	}
	return *ge.Reuse
}

// Covers: SEC-25 (part)
func TestRefreshReuseReportsWhatItEnded(t *testing.T) {
	e := newRefreshEnv(t)
	g0 := e.login(t, "web")
	e.mustRefresh(t, "web", g0.RefreshToken)
	sess := token.SessionID(e.refreshRow(t, g0.RefreshToken).SessionID)
	e.clock.Advance(grace)

	_, err := e.refresh("web", g0.RefreshToken)
	want := token.Reuse{Realm: e.rid, User: "u1", Client: "web", Session: sess, Kind: token.ReuseRefreshToken, Ended: true}
	if got := reuseOf(t, err); got != want {
		t.Fatalf("reuse = %+v, want %+v", got, want)
	}
	// The session is revoked now: a second presentation ends nothing.
	_, err = e.refresh("web", g0.RefreshToken)
	want.Ended = false
	if got := reuseOf(t, err); got != want {
		t.Fatalf("second reuse = %+v, want %+v", got, want)
	}
}

// Covers: SEC-25 (part)
func TestRefreshAfterLogoutReportsNothingEnded(t *testing.T) {
	e := newRefreshEnv(t)
	g0 := e.login(t, "web")
	sess := e.refreshRow(t, g0.RefreshToken).SessionID
	err := e.st.Write(context.Background(), func(tx store.Tx) error {
		_, err := tx.RefreshTokens().RevokeSession(context.Background(), e.rid, sess, e.clock.Now())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.refresh("web", g0.RefreshToken)
	if got := reuseOf(t, err); got.Ended || got.Kind != token.ReuseRefreshToken {
		t.Fatalf("reuse = %+v, want kind refresh_token and nothing ended", got)
	}
}

// Covers: SEC-25 (part)
func TestCodeReuseReportsWhatItEnded(t *testing.T) {
	e := newCodesEnv(t)
	code := e.issue(t, "web", "")
	g, err := e.codes.Exchange(context.Background(), e.in("web", code, cb, ""))
	if err != nil {
		t.Fatal(err)
	}
	sess := token.SessionID(e.refreshRow(t, g.RefreshToken).SessionID)

	_, err = e.codes.Exchange(context.Background(), e.in("web", code, cb, ""))
	want := token.Reuse{Realm: e.rid, User: "u1", Client: "web", Session: sess, Kind: token.ReuseCode, Ended: true}
	if got := reuseOf(t, err); got != want {
		t.Fatalf("reuse = %+v, want %+v", got, want)
	}
	_, err = e.codes.Exchange(context.Background(), e.in("web", code, cb, ""))
	want.Ended = false
	if got := reuseOf(t, err); got != want {
		t.Fatalf("second reuse = %+v, want %+v", got, want)
	}
}

// Covers: SEC-25 (part)
func TestFailedAuthNamesOnlyKnownConfidentialClient(t *testing.T) {
	r, sec, _ := clientAuthEnv(t)
	tests := []struct {
		name  string
		form  url.Values
		authz string
		want  config.ClientID // empty when the failure names no client
	}{
		{"known confidential, wrong secret in the body", url.Values{"client_id": {"srv"}, "client_secret": {"wrong"}}, "", "srv"},
		{"known confidential, no secret", url.Values{"client_id": {"srv"}}, "", "srv"},
		{"known confidential, wrong secret in Basic", nil, basic("srv", "wrong"), "srv"},
		{"public client that sends a secret", url.Values{"client_id": {"spa"}, "client_secret": {"x"}}, "", ""},
		{"unknown client", url.Values{"client_id": {"nobody"}, "client_secret": {"x"}}, "", ""},
		{"no client id", url.Values{}, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := token.AuthenticateClient(r, sec, tc.form, tc.authz)
			var ce *token.ClientAuthError
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v, want a client authentication error", err)
			}
			if ce.Client != tc.want {
				t.Fatalf("Client = %q, want %q", ce.Client, tc.want)
			}
		})
	}
}
