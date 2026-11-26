package oidc_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

const googleEventsURL = server.Issuer + "/events/google"

// secevent is the content type Google posts a security event token with (the
// service does not check it).
var secevent = http.Header{"Content-Type": {"application/secevent+jwt"}}

func postSET(t *testing.T, e *server.Env, token string) server.Response {
	t.Helper()
	return e.NewClient().Request(t, http.MethodPost, googleEventsURL, token, secevent)
}

// riscEvents is the events claim of a token with one event of the given type.
func riscEvents(typ string, body map[string]any) map[string]any {
	return map[string]any{"https://schemas.openid.net/secevent/risc/event-type/" + typ: body}
}

// riscAccount is the body of an event about the Google account sub.
func riscAccount(sub string) map[string]any {
	return map[string]any{"subject": map[string]any{"subject_type": "iss-sub", "iss": mockidp.RISCIssuer, "sub": sub}}
}

// googleLogin signs a user in through Google as the app that gets refresh tokens,
// with a browser session when sso is on, and returns the app, the refresh token
// and the browser session cookie.
func googleLogin(t *testing.T, e *server.Env, sub, email string) (server.App, string, string) {
	t.Helper()
	app := server.ClientDelete
	e.Mocks["google"].SetUser(mockidp.User{Sub: sub, Name: "Ann Lee", Email: email, EmailVerified: true})
	c := e.NewClient()
	g := e.Exchange(t, app, c.Login(t, server.Authorize(app, "google")))
	return app, g.RefreshToken, browserCookie(c)
}

func wantAccepted(t *testing.T, r server.Response) {
	t.Helper()
	if r.Code != http.StatusAccepted || r.Body != "" {
		t.Fatalf("status %d body %q, want 202 with no body", r.Code, r.Body)
	}
}

func wantRefusedAsInvalid(t *testing.T, r server.Response) {
	t.Helper()
	if r.Code != http.StatusBadRequest || !strings.Contains(r.Body, `"invalid_request"`) {
		t.Fatalf("status %d body %q, want 400 invalid_request", r.Code, r.Body)
	}
}

// googleAudits returns the identity.sessions_revoked rows of the provider google.
func googleAudits(t *testing.T, e *server.Env) []store.AuditEvent {
	t.Helper()
	var out []store.AuditEvent
	for _, a := range auditActions(t, e) {
		if a.Action == "identity.sessions_revoked" {
			out = append(out, a)
		}
	}
	return out
}

// Covers: FR-48, SEC-39
// Acceptance: Google security events
func TestGoogleSecurityEventsAcceptance(t *testing.T) {
	e := server.New(t)
	ssoOn(t, e)
	g := e.Mocks["google"]
	aud := g.ClientID()

	// Google's keys cannot be fetched before the first event is read: 503, and
	// nothing is acted on. Google sends the same token again at the end.
	app, rtF, _ := googleLogin(t, e, "g-8", "fay@example.com")
	outage := g.SecurityEvent(aud, riscEvents("sessions-revoked", riscAccount("g-8")))
	g.FailRISC(1)
	if r := postSET(t, e, outage); r.Code != http.StatusServiceUnavailable || !strings.Contains(r.Body, `"temporarily_unavailable"`) {
		t.Fatalf("status %d body %q, want 503 temporarily_unavailable", r.Code, r.Body)
	}
	wantAlive(t, e, app, rtF)

	// sessions-revoked: 202; the refresh token and the browser session end, the
	// identity and the user stay, and one identity.sessions_revoked row is written.
	_, rt, cookie := googleLogin(t, e, "g-1", "ann@example.com")
	revoke := g.SecurityEvent(aud, riscEvents("sessions-revoked", riscAccount("g-1")))
	wantAccepted(t, postSET(t, e, revoke))
	wantRevoked(t, e, app, rt)
	if _, ok := browserRow(t, e, cookie); ok {
		t.Error("the browser session survived sessions-revoked")
	}
	if _, err := identityOf(t, e, "google", "g-1"); err != nil {
		t.Error("the identity was removed")
	}
	rows := googleAudits(t, e)
	if len(rows) != 1 || rows[0].Actor != "provider:google" || rows[0].Details["event"] != "sessions-revoked" || rows[0].Details["provider"] != "google" {
		t.Fatalf("audit rows = %+v, want one identity.sessions_revoked", rows)
	}

	// The same token again changes nothing and is answered 202 again.
	wantAccepted(t, postSET(t, e, revoke))
	if n := len(googleAudits(t, e)); n != 1 {
		t.Errorf("%d identity.sessions_revoked rows after the repeat, want 1", n)
	}

	// Two events in one token, each about its own user: both are acted on.
	_, rtB, _ := googleLogin(t, e, "g-2", "bob@example.com")
	_, rtC, _ := googleLogin(t, e, "g-3", "carol@example.com")
	pair := map[string]any{}
	for k, v := range riscEvents("sessions-revoked", riscAccount("g-2")) {
		pair[k] = v
	}
	for k, v := range riscEvents("tokens-revoked", riscAccount("g-3")) {
		pair[k] = v
	}
	wantAccepted(t, postSET(t, e, g.SecurityEvent(aud, pair)))
	wantRevoked(t, e, app, rtB)
	wantRevoked(t, e, app, rtC)

	// account-disabled revokes the sessions as well, and its user is kept.
	_, rtE, cookieE := googleLogin(t, e, "g-7", "eli@example.com")
	wantAccepted(t, postSET(t, e, g.SecurityEvent(aud, riscEvents("account-disabled", riscAccount("g-7")))))
	wantRevoked(t, e, app, rtE)
	if _, ok := browserRow(t, e, cookieE); ok {
		t.Error("the browser session survived account-disabled")
	}
	// One row for each revoking event that ended a session: sessions-revoked,
	// the pair's sessions-revoked and tokens-revoked, and account-disabled.
	if n := len(googleAudits(t, e)); n != 4 {
		t.Errorf("%d identity.sessions_revoked rows, want 4 (one per revoking event that ended a session)", n)
	}

	// Other events are answered 202 and only logged: an account that is disabled
	// or re-enabled at Google, a token event (its subject is a token), a
	// verification, an unknown subject and a subject of another type.
	_, rtD, _ := googleLogin(t, e, "g-4", "dan@example.com")
	logged := []map[string]any{
		riscEvents("account-enabled", riscAccount("g-4")),
		riscEvents("account-credential-change-required", riscAccount("g-4")),
		riscEvents("token-revoked", map[string]any{"subject": map[string]any{"subject_type": "token", "token_type": "refresh_token", "token": "t"}}),
		riscEvents("verification", map[string]any{"state": "check-1"}),
		riscEvents("sessions-revoked", riscAccount("nobody")),
		riscEvents("sessions-revoked", map[string]any{"subject": map[string]any{"subject_type": "email", "email": "dan@example.com"}}),
	}
	before := len(googleAudits(t, e))
	for _, events := range logged {
		wantAccepted(t, postSET(t, e, g.SecurityEvent(aud, events)))
	}
	if n := len(googleAudits(t, e)); n != before {
		t.Errorf("logged events wrote %d audit rows", n-before)
	}
	wantAlive(t, e, app, rtD)

	// A token that does not verify is refused with 400 and changes nothing.
	before = len(googleAudits(t, e))
	const iatTooOld = 25 * time.Hour
	claims := func(mod func(c map[string]any)) string {
		c := map[string]any{
			"iss": mockidp.RISCIssuer, "aud": aud, "iat": e.Clock.Now().Unix(), "jti": "set-refused",
			"events": riscEvents("sessions-revoked", riscAccount("g-4")),
		}
		mod(c)
		return g.RISCToken(c)
	}
	refused := []struct {
		name  string
		token string
	}{
		{"a bad signature", claims(func(map[string]any) {}) + "A"},
		{"a wrong aud", claims(func(c map[string]any) { c["aud"] = "another-client" })},
		{"the ID token issuer", claims(func(c map[string]any) { c["iss"] = g.URL() })},
		{"an iat 25 hours old", claims(func(c map[string]any) { c["iat"] = e.Clock.Now().Add(-iatTooOld).Unix() })},
	}
	for _, r := range refused {
		t.Run(r.name, func(t *testing.T) {
			wantRefusedAsInvalid(t, postSET(t, e, r.token))
		})
	}
	wantAlive(t, e, app, rtD)
	if n := len(googleAudits(t, e)); n != before {
		t.Errorf("refused tokens wrote %d audit rows", n-before)
	}

	// The token that the outage refused is acted on when Google sends it again.
	wantAccepted(t, postSET(t, e, outage))
	wantRevoked(t, e, app, rtF)
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleEventKeysUnavailableIsRetried(t *testing.T) {
	e := server.New(t)
	app, rt, _ := googleLogin(t, e, "g-5", "eve@example.com")
	g := e.Mocks["google"]
	token := g.SecurityEvent(g.ClientID(), riscEvents("sessions-revoked", riscAccount("g-5")))
	g.FailRISC(1) // the configuration document answers 500 once
	r := postSET(t, e, token)
	if r.Code != http.StatusServiceUnavailable || !strings.Contains(r.Body, `"temporarily_unavailable"`) {
		t.Fatalf("status %d body %q, want 503 temporarily_unavailable", r.Code, r.Body)
	}
	wantAlive(t, e, app, rt)
	// Google sends the same token again, and it is acted on.
	wantAccepted(t, postSET(t, e, token))
	wantRevoked(t, e, app, rt)
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
// A verification event is logged with its state under verification_state; the
// token, its jti and the subject of a logged event never reach the log.
func TestGoogleLoggedEventsCarryNoTokenJtiOrSubject(t *testing.T) {
	e := server.New(t)
	g := e.Mocks["google"]
	// A login first: the realm's row is written by the first login in these tests.
	googleLogin(t, e, "g-0", "zed@example.com")
	const (
		state   = "check-LOGTEST-1"
		jti     = "jti-LOGTEST-42"
		subject = "gsub-LOGTEST-7731"
	)
	verification := g.RISCToken(map[string]any{
		"iss": mockidp.RISCIssuer, "aud": g.ClientID(), "iat": e.Clock.Now().Unix(), "jti": jti,
		"events": riscEvents("verification", map[string]any{"state": state}),
	})
	wantAccepted(t, postSET(t, e, verification))
	account := g.RISCToken(map[string]any{
		"iss": mockidp.RISCIssuer, "aud": g.ClientID(), "iat": e.Clock.Now().Unix(), "jti": "jti-LOGTEST-43",
		"events": riscEvents("account-enabled", riscAccount(subject)),
	})
	wantAccepted(t, postSET(t, e, account))

	logs := e.Logs.String()
	if !strings.Contains(logs, "verification_state") || !strings.Contains(logs, state) {
		t.Errorf("the verification state is not logged under verification_state:\n%s", logs)
	}
	for _, secret := range []string{verification, account, jti, subject} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log holds %q", secret)
		}
	}
}

// googleIssuerEnv starts a service whose Google RISC document names issuer ("" for
// the mock's default), before any event is read.
func googleIssuerEnv(t *testing.T, issuer string) *server.Env {
	t.Helper()
	e := server.New(t)
	ssoOn(t, e)
	if issuer != "" {
		e.Mocks["google"].SetRISCIssuer(issuer)
	}
	return e
}

// The token's iss is accepted when it is the document's issuer or differs by one
// trailing slash, in both directions; every other iss is refused with 400 and
// changes nothing (FR-48). Two slashes never match, against a document issuer
// without a slash or with one.
// Covers: FR-48
// Acceptance: Google issuer with a trailing slash
func TestGoogleEventIssuerWithATrailingSlashAnswers(t *testing.T) {
	const g = mockidp.RISCIssuer
	for _, doc := range []string{"", g + "/"} {
		rows := []struct {
			name   string
			iss    string
			accept bool
		}{
			{"the issuer", g, true},
			{"the issuer plus a slash", g + "/", true},
			{"the issuer plus two slashes", g + "//", false},
			{"an upper-case scheme", "HTTPS://accounts.google.com", false},
			{"an upper-case host", "https://Accounts.google.com", false},
			{"http", "http://accounts.google.com", false},
			{"without a scheme", "accounts.google.com", false},
			{"with a path", g + "/x", false},
			{"with a leading space", " " + g, false},
			{"empty", "", false},
		}
		for _, r := range rows {
			t.Run("document "+doc+" iss "+r.name, func(t *testing.T) {
				e := googleIssuerEnv(t, doc)
				g := e.Mocks["google"]
				app, rt, _ := googleLogin(t, e, "g-1", "ann@example.com")
				token := g.RISCToken(map[string]any{
					"iss": r.iss, "aud": g.ClientID(), "iat": e.Clock.Now().Unix(), "jti": "set-iss",
					"events": riscEvents("sessions-revoked", riscAccount("g-1")),
				})
				resp := postSET(t, e, token)
				if r.accept {
					wantAccepted(t, resp)
					wantRevoked(t, e, app, rt)
					return
				}
				wantRefusedAsInvalid(t, resp)
				wantAlive(t, e, app, rt)
				if n := len(googleAudits(t, e)); n != 0 {
					t.Errorf("a refused token wrote %d audit rows", n)
				}
			})
		}
	}
}

// The issuer inside an event's iss-sub subject follows the same rule: the exact
// issuer and one slash more or less are acted on; two slashes and another case
// are logged as an unknown subject and not acted on, and the answer is 202.
// Covers: FR-48
// Acceptance: Google issuer with a trailing slash
func TestGoogleEventSubjectIssuerWithATrailingSlashAnswers(t *testing.T) {
	const g = mockidp.RISCIssuer
	rows := []struct {
		name  string
		doc   string
		iss   string
		acted bool
	}{
		{"the issuer", "", g, true},
		{"one trailing slash", "", g + "/", true},
		{"two trailing slashes", "", g + "//", false},
		{"an upper-case host", "", "https://Accounts.google.com", false},
		{"the document's slash and the exact issuer", g + "/", g, true},
		{"the document's slash and the same", g + "/", g + "/", true},
		{"the document's slash and two slashes", g + "/", g + "//", false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			e := googleIssuerEnv(t, r.doc)
			gm := e.Mocks["google"]
			app, rt, _ := googleLogin(t, e, "g-1", "ann@example.com")
			iss := mockidp.RISCIssuer
			if r.doc != "" {
				iss = r.doc
			}
			subject := map[string]any{"subject": map[string]any{"subject_type": "iss-sub", "iss": r.iss, "sub": "g-1"}}
			token := gm.RISCToken(map[string]any{
				"iss": iss, "aud": gm.ClientID(), "iat": e.Clock.Now().Unix(), "jti": "set-sub",
				"events": riscEvents("sessions-revoked", subject),
			})
			wantAccepted(t, postSET(t, e, token))
			if r.acted {
				wantRevoked(t, e, app, rt)
				if n := len(googleAudits(t, e)); n != 1 {
					t.Errorf("%d identity.sessions_revoked rows, want 1", n)
				}
				return
			}
			wantAlive(t, e, app, rt)
			if n := len(googleAudits(t, e)); n != 0 {
				t.Errorf("an event with another subject issuer wrote %d audit rows", n)
			}
			if !strings.Contains(e.Logs.String(), "provider event for an unknown subject ignored") {
				t.Errorf("the event was not logged as an unknown subject:\n%s", e.Logs.String())
			}
		})
	}
}

// A document issuer that is empty, "/" or ends in "//" matches nothing, so every
// token is refused with 400 and changes nothing, whatever its iss (FR-48).
// Covers: FR-48
// Acceptance: Google issuer with a trailing slash
func TestGoogleEventDegenerateDocumentIssuerRefusesEveryToken(t *testing.T) {
	const g = mockidp.RISCIssuer
	for _, doc := range []string{"", "/", g + "//", "//"} {
		for _, iss := range []string{doc, doc + "/", g, g + "/", "", "/"} {
			t.Run(fmt.Sprintf("document %q iss %q", doc, iss), func(t *testing.T) {
				e := server.New(t)
				ssoOn(t, e)
				gm := e.Mocks["google"]
				gm.SetRISCIssuer(doc)
				app, rt, _ := googleLogin(t, e, "g-1", "ann@example.com")
				token := gm.RISCToken(map[string]any{
					"iss": iss, "aud": gm.ClientID(), "iat": e.Clock.Now().Unix(), "jti": "set-degenerate",
					"events": riscEvents("sessions-revoked", riscAccount("g-1")),
				})
				wantRefusedAsInvalid(t, postSET(t, e, token))
				wantAlive(t, e, app, rt)
				if n := len(googleAudits(t, e)); n != 0 {
					t.Errorf("a refused token wrote %d audit rows", n)
				}
			})
		}
	}
}
