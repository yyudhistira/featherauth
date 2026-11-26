package oidc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

const metaURL = server.Issuer + "/events/facebook"

var code22 = regexp.MustCompile(`^[A-Za-z0-9]{22}$`)

// metaRequest posts a form with the signed_request values, as Meta does.
func metaRequest(t *testing.T, e *server.Env, signed ...string) server.Response {
	t.Helper()
	return e.NewClient().Request(t, http.MethodPost, metaURL, url.Values{"signed_request": signed}.Encode(),
		http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
}

// metaSigned is a signed_request for user_id, issued at issued, under the
// secret of the Facebook provider.
func metaSigned(e *server.Env, userID string, issued time.Time, mod func(m map[string]any)) string {
	m := map[string]any{"algorithm": "HMAC-SHA256", "issued_at": issued.Unix(), "user_id": userID}
	if mod != nil {
		mod(m)
	}
	return mockidp.SignedRequest(e.Mocks["facebook"].ClientSecret(), m)
}

// wantMetaAnswer checks the answer Meta needs: 200 JSON with exactly the url
// and the confirmation code, which is 22 letters and digits, and no-store. It
// returns the code.
func wantMetaAnswer(t *testing.T, r server.Response) string {
	t.Helper()
	if r.Code != http.StatusOK {
		t.Fatalf("status %d %q, want 200", r.Code, r.Body)
	}
	if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
		t.Errorf("headers %v", r.Header)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(r.Body), &got); err != nil || len(got) != 2 {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	if !code22.MatchString(got["confirmation_code"]) || got["url"] != server.Issuer+"/data-deletion?code="+got["confirmation_code"] {
		t.Fatalf("answer %v", got)
	}
	return got["confirmation_code"]
}

// wantMetaRefused checks a refusal: 400 invalid_request with no-store.
func wantMetaRefused(t *testing.T, r server.Response) {
	t.Helper()
	if r.Code != http.StatusBadRequest || wantJSONError(t, r) != "invalid_request" || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
		t.Errorf("status %d headers %v body %q, want 400 invalid_request with no-store", r.Code, r.Header, r.Body)
	}
}

// facebookLoginGrant signs a user in through Facebook.
func facebookLoginGrant(t *testing.T, e *server.Env, sub string) (server.App, string) {
	t.Helper()
	app := server.ClientDelete
	e.Mocks["facebook"].SetUser(mockidp.User{Sub: sub, Name: "Ann Lee", Email: "ann@example.com"})
	g := e.Exchange(t, app, e.NewClient().Login(t, server.Authorize(app, "facebook")))
	return app, g.RefreshToken
}

// linkGoogle adds a Google identity to the user of the Facebook identity.
func linkGoogle(t *testing.T, e *server.Env, fbSub string) {
	t.Helper()
	fb, err := identityOf(t, e, "facebook", fbSub)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	err = e.Store.Write(ctx, func(tx store.Tx) error {
		return tx.Identities().Create(ctx, store.Identity{
			ID: "g-ident", RealmID: fb.RealmID, UserID: fb.UserID, Provider: "google", ProviderSub: "g-1", CreatedAt: e.Clock.Now(),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

// writes runs f and returns how many write transactions it started.
func writes(e *server.Env, f func()) int {
	before := e.Faults.Writes()
	f()
	return e.Faults.Writes() - before
}

// Covers: FR-40, SEC-33
// Acceptance: Meta deletion callback
func TestMetaDeletionOfAFacebookOnlyUser(t *testing.T) {
	e := server.New(t)
	app, rt := facebookLoginGrant(t, e, "fb-subject-unlikely-4711")
	var r server.Response
	if n := writes(e, func() { r = metaRequest(t, e, metaSigned(e, "fb-subject-unlikely-4711", e.Clock.Now(), nil)) }); n != 1 {
		t.Errorf("%d write transactions, want 1", n)
	}
	first := wantMetaAnswer(t, r)
	if _, err := identityOf(t, e, "facebook", "fb-subject-unlikely-4711"); err == nil {
		t.Fatal("the user is still there")
	}
	wantRevoked(t, e, app, rt)
	rows := auditActions(t, e)
	if len(rows) != 1 || rows[0].Action != "user.delete" || rows[0].Actor != "provider:facebook" {
		t.Fatalf("audit = %+v", rows)
	}
	if n := len(e.Mocks["facebook"].Revocations()); n != 0 {
		t.Errorf("%d calls to Facebook, want none", n)
	}

	t.Run("the same request again changes nothing and is answered again", func(t *testing.T) {
		second := wantMetaAnswer(t, metaRequest(t, e, metaSigned(e, "fb-subject-unlikely-4711", e.Clock.Now(), nil)))
		if second == first {
			t.Error("the repeat got the same code")
		}
		if n := len(auditActions(t, e)); n != 1 {
			t.Errorf("%d audit rows after the repeat, want 1", n)
		}
	})
}

// Covers: FR-40, SEC-33
// Acceptance: Meta deletion callback
func TestMetaUnlinksTheFacebookIdentityOfAUserWithGoogle(t *testing.T) {
	e := server.New(t)
	app, rt := facebookLoginGrant(t, e, "fb-subject-unlikely-4711")
	linkGoogle(t, e, "fb-subject-unlikely-4711")
	fb, _ := identityOf(t, e, "facebook", "fb-subject-unlikely-4711")
	sr := metaSigned(e, "fb-subject-unlikely-4711", e.Clock.Now(), nil)

	wantMetaAnswer(t, metaRequest(t, e, sr))
	if _, err := identityOf(t, e, "facebook", "fb-subject-unlikely-4711"); err == nil {
		t.Error("the Facebook identity is still linked")
	}
	if g, err := identityOf(t, e, "google", "g-1"); err != nil || g.UserID != fb.UserID {
		t.Errorf("the Google identity: %+v %v", g, err)
	}
	wantRevoked(t, e, app, rt)
	rows := auditActions(t, e)
	if len(rows) != 1 || rows[0].Action != "identity.unlink" || rows[0].Actor != "provider:facebook" {
		t.Fatalf("audit = %+v", rows)
	}

	t.Run("the signature re-encoded with padding is the same request", func(t *testing.T) {
		sig, part, _ := strings.Cut(sr, ".")
		wantMetaAnswer(t, metaRequest(t, e, sig+"=."+part))
		if n := len(auditActions(t, e)); n != 1 {
			t.Errorf("%d audit rows, want 1", n)
		}
	})
	t.Run("it is still remembered 59 minutes later and refused after the hour", func(t *testing.T) {
		e.Clock.Advance(59 * time.Minute)
		wantMetaAnswer(t, metaRequest(t, e, sr)) // issued 59 minutes ago, remembered
		if n := len(auditActions(t, e)); n != 1 {
			t.Errorf("%d audit rows, want 1", n)
		}
		e.Clock.Advance(2 * time.Minute) // now 61 minutes old
		wantMetaRefused(t, metaRequest(t, e, sr))
	})
}

// Covers: FR-40, SEC-33
// Acceptance: Meta deletion callback
func TestMetaRefusesBadRequests(t *testing.T) {
	now := func(e *server.Env) time.Time { return e.Clock.Now() }
	rows := []struct {
		name string
		body func(e *server.Env) []string
	}{
		{"no signed_request", func(e *server.Env) []string { return nil }},
		{"an empty signed_request", func(e *server.Env) []string { return []string{""} }},
		{"two signed_requests", func(e *server.Env) []string {
			s := metaSigned(e, "fb-subject-unlikely-4711", now(e), nil)
			return []string{s, s}
		}},
		{"one part", func(e *server.Env) []string { return []string{"abc"} }},
		{"three parts", func(e *server.Env) []string {
			return []string{metaSigned(e, "fb-subject-unlikely-4711", now(e), nil) + ".x"}
		}},
		{"a bad signature", func(e *server.Env) []string {
			_, part, _ := strings.Cut(metaSigned(e, "fb-subject-unlikely-4711", now(e), nil), ".")
			return []string{"AAAA." + part}
		}},
		{"another secret", func(e *server.Env) []string {
			return []string{mockidp.SignedRequest("another-secret", map[string]any{"algorithm": "HMAC-SHA256", "issued_at": now(e).Unix(), "user_id": "fb-subject-unlikely-4711"})}
		}},
		{"a payload that is not JSON", func(e *server.Env) []string {
			return []string{mockidp.SignedPart(e.Mocks["facebook"].ClientSecret(), "bm90IGpzb24")}
		}},
		{"another algorithm", func(e *server.Env) []string {
			return []string{metaSigned(e, "fb-subject-unlikely-4711", now(e), func(m map[string]any) { m["algorithm"] = "HMAC-SHA1" })}
		}},
		{"issued two hours ago", func(e *server.Env) []string {
			return []string{metaSigned(e, "fb-subject-unlikely-4711", now(e).Add(-2*time.Hour), nil)}
		}},
		{"issued five minutes and a second ahead", func(e *server.Env) []string {
			return []string{metaSigned(e, "fb-subject-unlikely-4711", now(e).Add(5*time.Minute+time.Second), nil)}
		}},
		{"no issued_at", func(e *server.Env) []string {
			return []string{metaSigned(e, "fb-subject-unlikely-4711", now(e), func(m map[string]any) { delete(m, "issued_at") })}
		}},
		{"no user_id", func(e *server.Env) []string {
			return []string{metaSigned(e, "fb-subject-unlikely-4711", now(e), func(m map[string]any) { delete(m, "user_id") })}
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			e := server.New(t)
			app, rt := facebookLoginGrant(t, e, "fb-subject-unlikely-4711")
			var r server.Response
			if n := writes(e, func() { r = metaRequest(t, e, row.body(e)...) }); n != 0 {
				t.Errorf("%d write transactions, want 0", n)
			}
			wantMetaRefused(t, r)
			if _, err := identityOf(t, e, "facebook", "fb-subject-unlikely-4711"); err != nil {
				t.Error("the user was changed")
			}
			wantAlive(t, e, app, rt)
			if n := len(auditActions(t, e)); n != 0 {
				t.Errorf("%d audit rows, want none", n)
			}
			// Nothing was remembered: the valid request still acts.
			wantMetaAnswer(t, metaRequest(t, e, metaSigned(e, "fb-subject-unlikely-4711", now(e), nil)))
			if _, err := identityOf(t, e, "facebook", "fb-subject-unlikely-4711"); err == nil {
				t.Error("the valid request that followed did not act")
			}
		})
	}
	t.Run("a body that is not a form", func(t *testing.T) {
		e := server.New(t)
		r := e.NewClient().Request(t, http.MethodPost, metaURL, "signed_request=%zz", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		wantMetaRefused(t, r)
	})
}

// Covers: FR-40, SEC-33
// Acceptance: Meta deletion callback
func TestMetaAcceptsTheBoundariesAndAnyContentType(t *testing.T) {
	for name, issued := range map[string]func(now time.Time) time.Time{
		"exactly an hour old":        func(now time.Time) time.Time { return now.Add(-time.Hour) },
		"exactly five minutes ahead": func(now time.Time) time.Time { return now.Add(5 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			e := server.New(t)
			facebookLoginGrant(t, e, "fb-subject-unlikely-4711")
			wantMetaAnswer(t, metaRequest(t, e, metaSigned(e, "fb-subject-unlikely-4711", issued(e.Clock.Now()), nil)))
			if _, err := identityOf(t, e, "facebook", "fb-subject-unlikely-4711"); err == nil {
				t.Error("the user is still there")
			}
		})
	}
	t.Run("no content type", func(t *testing.T) {
		e := server.New(t)
		facebookLoginGrant(t, e, "fb-subject-unlikely-4711")
		body := url.Values{"signed_request": {metaSigned(e, "fb-subject-unlikely-4711", e.Clock.Now(), nil)}}.Encode()
		wantMetaAnswer(t, e.NewClient().Request(t, http.MethodPost, metaURL, body, nil))
		if _, err := identityOf(t, e, "facebook", "fb-subject-unlikely-4711"); err == nil {
			t.Error("the user is still there")
		}
	})
	t.Run("an unknown user_id is answered and remembered, and changes nothing", func(t *testing.T) {
		e := server.New(t)
		app, rt := facebookLoginGrant(t, e, "fb-subject-unlikely-4711")
		sr := metaSigned(e, "nobody", e.Clock.Now(), nil)
		var r server.Response
		if n := writes(e, func() { r = metaRequest(t, e, sr) }); n != 1 {
			t.Errorf("%d write transactions, want 1", n)
		}
		wantMetaAnswer(t, r)
		wantMetaAnswer(t, metaRequest(t, e, sr))
		if n := len(auditActions(t, e)); n != 0 {
			t.Errorf("%d audit rows, want none", n)
		}
		wantAlive(t, e, app, rt)
	})
}

// Covers: FR-40, SEC-33
// Acceptance: Meta deletion callback
func TestMetaStoreFailureRemembersNothing(t *testing.T) {
	e := server.New(t)
	facebookLoginGrant(t, e, "fb-subject-unlikely-4711")
	sr := metaSigned(e, "fb-subject-unlikely-4711", e.Clock.Now(), nil)
	e.Faults.Fail("Users.Delete", fmt.Errorf("disk on fire"))
	r := metaRequest(t, e, sr)
	e.Faults.Fail("Users.Delete", nil)
	if r.Code != 500 || wantJSONError(t, r) != "server_error" || r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("status %d headers %v body %q, want 500 server_error with no-store", r.Code, r.Header, r.Body)
	}
	if _, err := identityOf(t, e, "facebook", "fb-subject-unlikely-4711"); err != nil {
		t.Fatal("a failed change deleted the user")
	}
	// Facebook's retry is acted on, because nothing was remembered.
	wantMetaAnswer(t, metaRequest(t, e, sr))
	if _, err := identityOf(t, e, "facebook", "fb-subject-unlikely-4711"); err == nil {
		t.Error("the retry did not act")
	}
	if n := len(auditActions(t, e)); n != 1 {
		t.Errorf("%d audit rows, want 1", n)
	}
}

// Covers: FR-40, SEC-33, SEC-13 (part)
// Acceptance: Meta deletion callback
func TestMetaLogsNeitherTheRequestNorTheSecret(t *testing.T) {
	e := server.New(t)
	facebookLoginGrant(t, e, "fb-subject-unlikely-4711")
	valid := metaSigned(e, "fb-subject-unlikely-4711", e.Clock.Now(), nil)
	sig, part, _ := strings.Cut(valid, ".")
	bad := metaSigned(e, "fb-2", e.Clock.Now().Add(-2*time.Hour), nil)
	badSig, badPart, _ := strings.Cut(bad, ".")
	e.Logs.Reset()
	wantMetaAnswer(t, metaRequest(t, e, valid))
	wantMetaAnswer(t, metaRequest(t, e, valid)) // the repeat
	wantMetaRefused(t, metaRequest(t, e, bad))
	wantMetaRefused(t, metaRequest(t, e, "x"+valid))
	logs := e.Logs.String()
	for name, secret := range map[string]string{
		"the client secret": e.Mocks["facebook"].ClientSecret(), "the signed request": valid, "its signature": sig, "its payload": part,
		"a refused request": bad, "its signature part": badSig, "its payload part": badPart, "the Facebook subject": "fb-subject-unlikely-4711",
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log holds %s", name)
		}
	}
	if !strings.Contains(logs, `"provider":"facebook"`) {
		t.Errorf("no log line names the provider: %s", logs)
	}
}
