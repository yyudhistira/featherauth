package provider_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

var (
	_ provider.EventReceiver = (*provider.Google)(nil)
	_ provider.EventAnswerer = (*provider.Google)(nil)
)

// riscEventType is the prefix of Google's event type URIs; a test names the
// event by its last part.
const riscEventType = "https://schemas.openid.net/secevent/risc/event-type/"

// newGoogleEvents returns a Google adapter whose RISC configuration is the
// mock's, with the mock and the fake clock of the adapter (at eventTime).
func newGoogleEvents(t testing.TB) (*provider.Google, *mockidp.Server, *clock.Fake) {
	t.Helper()
	return newGoogleEventsAt(t, func(srv *mockidp.Server) string { return srv.URL() + mockidp.RISCConfigPath })
}

// newGoogleEventsAt is newGoogleEvents with the RISC configuration URL that risc
// returns for the mock.
func newGoogleEventsAt(t testing.TB, risc func(srv *mockidp.Server) string) (*provider.Google, *mockidp.Server, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(eventTime)
	srv := mockidp.New(t, clk, mockidp.Google)
	p, err := provider.NewGoogle(context.Background(), provider.GoogleOptions{
		OIDCOptions: provider.OIDCOptions{
			Issuer: srv.URL(), ClientID: srv.ClientID(), ClientSecret: srv.ClientSecret(),
			RedirectURI: "https://featherauth.example/realm/callback/google", Scopes: []string{"openid"},
			Timeout: 5 * time.Second, Clock: clk,
		},
		RISCConfigurationURL: risc(srv),
	})
	if err != nil {
		t.Fatalf("NewGoogle: %v", err)
	}
	return p, srv, clk
}

// accountEvent is the body of an event about a Google account (subject_type iss-sub).
func accountEvent(sub string) map[string]any {
	return map[string]any{"subject": map[string]any{"subject_type": "iss-sub", "iss": mockidp.RISCIssuer, "sub": sub}}
}

// tokenClaims are the claims of a valid security event token issued at iat with
// these events; a test changes them before it signs them.
func tokenClaims(srv *mockidp.Server, iat time.Time, events map[string]any) map[string]any {
	return map[string]any{"iss": mockidp.RISCIssuer, "aud": srv.ClientID(), "iat": iat.Unix(), "jti": "set-1", "events": events}
}

// oneEvent is the events claim of a token with one event of the given type.
func oneEvent(typ string, body map[string]any) map[string]any {
	return map[string]any{riscEventType + typ: body}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleEventTypesOfTheTable(t *testing.T) {
	p, srv, _ := newGoogleEvents(t)
	rows := []struct {
		typ, sub, state string
		body            map[string]any
	}{
		{typ: "sessions-revoked", sub: "g-1", body: accountEvent("g-1")},
		{typ: "tokens-revoked", sub: "g-1", body: accountEvent("g-1")},
		{typ: "account-disabled", sub: "g-1", body: map[string]any{
			"subject": map[string]any{"subject_type": "iss-sub", "iss": mockidp.RISCIssuer, "sub": "g-1"}, "reason": "hijacking"}},
		{typ: "account-enabled", sub: "g-1", body: accountEvent("g-1")},
		{typ: "account-credential-change-required", sub: "g-1", body: accountEvent("g-1")},
		{typ: "token-revoked", sub: "", body: map[string]any{
			"subject": map[string]any{"subject_type": "token", "token_type": "refresh_token", "token": "t-1"}}},
		{typ: "verification", state: "check-1", body: map[string]any{"state": "check-1"}},
	}
	for _, r := range rows {
		t.Run(r.typ, func(t *testing.T) {
			body := srv.RISCToken(tokenClaims(srv, eventTime, oneEvent(r.typ, r.body)))
			evs, err := p.ParseEvent(context.Background(), []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if len(evs) != 1 {
				t.Fatalf("%d events, want 1", len(evs))
			}
			ev := evs[0]
			if ev.Set != provider.EventSetGoogle || ev.Type != r.typ || ev.Subject != r.sub || ev.State != r.state || ev.ID != "set-1" || !ev.Expires.Equal(eventTime.Add(24*time.Hour)) {
				t.Errorf("event = %+v, want type %s subject %q state %q id set-1 expiring 24h after the iat", ev, r.typ, r.sub, r.state)
			}
		})
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleEventTokenWithTwoEvents(t *testing.T) {
	p, srv, _ := newGoogleEvents(t)
	events := map[string]any{riscEventType + "sessions-revoked": accountEvent("g-1")}
	events[riscEventType+"account-disabled"] = accountEvent("g-1")
	evs, err := p.ParseEvent(context.Background(), []byte(srv.RISCToken(tokenClaims(srv, eventTime, events))))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, ev := range evs {
		got[ev.Type] = ev.Subject == "g-1" && ev.ID == "set-1"
	}
	if len(evs) != 2 || !got["sessions-revoked"] || !got["account-disabled"] {
		t.Errorf("events = %+v, want both events about g-1 with the jti of the token", evs)
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleEventRefusals(t *testing.T) {
	p, srv, _ := newGoogleEvents(t)
	rows := []struct {
		name string
		body func(t *testing.T) string
	}{
		{"a signature that does not match", func(*testing.T) string {
			tok := srv.RISCToken(tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1"))))
			// A character of the signature's middle: the last one carries unused bits.
			i := len(tok) - 20
			flipped := byte('A')
			if tok[i] == 'A' {
				flipped = 'B'
			}
			return tok[:i] + string(flipped) + tok[i+1:]
		}},
		{"a token signed with the ID token key", func(t *testing.T) string {
			c := tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1")))
			var w struct {
				Payload string `json:"payload"`
			}
			if err := json.Unmarshal([]byte(srv.SignedClaims(c)), &w); err != nil {
				t.Fatal(err)
			}
			return w.Payload
		}},
		{"a wrong audience", func(*testing.T) string {
			c := tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1")))
			c["aud"] = "another-client"
			return srv.RISCToken(c)
		}},
		{"the ID token issuer in place of the RISC issuer", func(*testing.T) string {
			c := tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1")))
			c["iss"] = srv.URL()
			return srv.RISCToken(c)
		}},
		{"an iat 25 hours old", func(*testing.T) string {
			return srv.RISCToken(tokenClaims(srv, eventTime.Add(-25*time.Hour), oneEvent("sessions-revoked", accountEvent("g-1"))))
		}},
		{"an iat more than 5 minutes ahead", func(*testing.T) string {
			return srv.RISCToken(tokenClaims(srv, eventTime.Add(5*time.Minute+time.Second), oneEvent("sessions-revoked", accountEvent("g-1"))))
		}},
		{"no iat", func(*testing.T) string {
			c := tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1")))
			delete(c, "iat")
			return srv.RISCToken(c)
		}},
		{"no jti", func(*testing.T) string {
			c := tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1")))
			delete(c, "jti")
			return srv.RISCToken(c)
		}},
		{"no events", func(*testing.T) string {
			c := tokenClaims(srv, eventTime, nil)
			delete(c, "events")
			return srv.RISCToken(c)
		}},
		{"events that is not an object", func(*testing.T) string {
			c := tokenClaims(srv, eventTime, nil)
			c["events"] = "sessions-revoked"
			return srv.RISCToken(c)
		}},
		{"an event that is not an object", func(*testing.T) string {
			return srv.RISCToken(tokenClaims(srv, eventTime, map[string]any{riscEventType + "sessions-revoked": "g-1"}))
		}},
		{"a body that is not a token", func(*testing.T) string { return "not a token" }},
		{"an empty body", func(*testing.T) string { return "" }},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			_, err := p.ParseEvent(context.Background(), []byte(r.body(t)))
			if !errors.Is(err, provider.ErrInvalidEvent) {
				t.Fatalf("err = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleEventIssuedAtBoundaries(t *testing.T) {
	p, srv, _ := newGoogleEvents(t)
	rows := []struct {
		name    string
		iat     time.Time
		expires time.Time
	}{
		// 24 hours old is still accepted, and remembered from now.
		{"24 hours old", eventTime.Add(-24 * time.Hour), eventTime.Add(24 * time.Hour)},
		// 5 minutes ahead is still accepted, and remembered from its iat.
		{"5 minutes ahead", eventTime.Add(5 * time.Minute), eventTime.Add(5*time.Minute + 24*time.Hour)},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			body := srv.RISCToken(tokenClaims(srv, r.iat, oneEvent("sessions-revoked", accountEvent("g-1"))))
			evs, err := p.ParseEvent(context.Background(), []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if len(evs) != 1 || !evs[0].Expires.Equal(r.expires) {
				t.Errorf("events = %+v, want one expiring %s", evs, r.expires)
			}
		})
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleEventAudienceList(t *testing.T) {
	p, srv, _ := newGoogleEvents(t)
	c := tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1")))
	c["aud"] = []string{"another-client", srv.ClientID()}
	if _, err := p.ParseEvent(context.Background(), []byte(srv.RISCToken(c))); err != nil {
		t.Fatalf("an audience list with our client id: %v", err)
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleEventSubjectsThatAreNotOurs(t *testing.T) {
	p, srv, _ := newGoogleEvents(t)
	rows := []struct {
		name string
		body map[string]any
	}{
		{"another subject type", map[string]any{"subject": map[string]any{"subject_type": "email", "email": "ann@example.com"}}},
		{"an iss-sub of another issuer", map[string]any{"subject": map[string]any{"subject_type": "iss-sub", "iss": "https://other.example", "sub": "g-1"}}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			body := srv.RISCToken(tokenClaims(srv, eventTime, oneEvent("sessions-revoked", r.body)))
			evs, err := p.ParseEvent(context.Background(), []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if len(evs) != 1 || evs[0].Subject != "" {
				t.Errorf("events = %+v, want one event with no subject", evs)
			}
		})
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleEventWithNoEventsAcceptedWithoutAction(t *testing.T) {
	p, srv, _ := newGoogleEvents(t)
	evs, err := p.ParseEvent(context.Background(), []byte(srv.RISCToken(tokenClaims(srv, eventTime, map[string]any{}))))
	if err != nil || len(evs) != 0 {
		t.Fatalf("events = %+v, %v; want none and no error", evs, err)
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleEventKeysAndDocumentUnavailable(t *testing.T) {
	p, srv, _ := newGoogleEvents(t)
	body := []byte(srv.RISCToken(tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1")))))
	srv.FailRISC(1) // the configuration document answers 500 once
	if _, err := p.ParseEvent(context.Background(), body); !errors.Is(err, provider.ErrUnavailable) || errors.Is(err, provider.ErrInvalidEvent) {
		t.Fatalf("document 500: err = %v, want ErrUnavailable only", err)
	}
	if _, err := p.ParseEvent(context.Background(), body); err != nil {
		t.Fatalf("after the document is back: %v", err)
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleEventRedirectsAndBadDocumentAreUnavailable(t *testing.T) {
	p, srv, _ := newGoogleEvents(t)
	body := []byte(srv.RISCToken(tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1")))))
	// A redirect is never followed: the target is not called.
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a redirect of the RISC configuration was followed")
	}))
	t.Cleanup(target.Close)
	srv.RedirectTo("risc", target.URL)
	if _, err := p.ParseEvent(context.Background(), body); !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("redirected document: err = %v, want ErrUnavailable", err)
	}
	srv.RedirectTo("risc", "")
	srv.RedirectTo("risc-jwks", target.URL)
	if _, err := p.ParseEvent(context.Background(), body); !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("redirected keys: err = %v, want ErrUnavailable", err)
	}
	srv.RedirectTo("risc-jwks", "")
	if _, err := p.ParseEvent(context.Background(), body); err != nil {
		t.Fatalf("after the redirects end: %v", err)
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleRISCDocumentWithoutIssuerOrKeysIsUnavailable(t *testing.T) {
	for _, doc := range []string{`{"issuer":"` + mockidp.RISCIssuer + `"}`, `{"jwks_uri":"https://keys.example/jwks"}`, `not json`} {
		t.Run(doc, func(t *testing.T) {
			bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(doc))
			}))
			t.Cleanup(bad.Close)
			p, srv, _ := newGoogleEventsAt(t, func(*mockidp.Server) string { return bad.URL })
			body := []byte(srv.RISCToken(tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1")))))
			if _, err := p.ParseEvent(context.Background(), body); !errors.Is(err, provider.ErrUnavailable) {
				t.Fatalf("err = %v, want ErrUnavailable", err)
			}
		})
	}
}

// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func TestGoogleRISCDocumentAndKeysAreReadOnce(t *testing.T) {
	p, srv, _ := newGoogleEvents(t)
	body := []byte(srv.RISCToken(tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1")))))
	for range 3 {
		if _, err := p.ParseEvent(context.Background(), body); err != nil {
			t.Fatal(err)
		}
	}
	calls := map[string]int{}
	for _, r := range srv.Requests() {
		calls[r.Path]++
	}
	if calls[mockidp.RISCConfigPath] != 1 || calls["/risc-jwks"] != 1 {
		t.Errorf("document calls %d, key calls %d; want 1 and 1", calls[mockidp.RISCConfigPath], calls["/risc-jwks"])
	}
}

// Covers: FR-48 (part)
// Acceptance: Google security events (part)
func TestGoogleEventsAreAnsweredWith202(t *testing.T) {
	p, _, _ := newGoogleEvents(t)
	if got := p.EventStatus(); got != http.StatusAccepted {
		t.Errorf("EventStatus = %d, want %d", got, http.StatusAccepted)
	}
}

// Covers: FR-48 (part)
// Acceptance: Google security events (part)
func TestGoogleRISCConfigurationDefaultIsGoogles(t *testing.T) {
	const want = "https://accounts.google.com/.well-known/risc-configuration"
	if provider.GoogleRISCConfigurationURL != want {
		t.Errorf("default = %q, want %q", provider.GoogleRISCConfigurationURL, want)
	}
}

// The issuer of the token and of an event's iss-sub subject match the document's
// issuer when byte equal or when one is the other plus exactly one trailing
// slash (FR-48); nothing else is normalised.
// Covers: FR-48
func TestGoogleEventIssuerWithATrailingSlash(t *testing.T) {
	const g = mockidp.RISCIssuer
	rows := []struct {
		name   string
		doc    string // the document's issuer; "" for the mock's default
		iss    string // the token's iss
		accept bool
	}{
		{"the exact issuer", "", g, true},
		{"the issuer plus a slash", "", g + "/", true},
		{"the issuer plus two slashes", "", g + "//", false},
		{"an upper-case scheme", "", "HTTPS://accounts.google.com", false},
		{"an upper-case host", "", "https://Accounts.google.com", false},
		{"http", "", "http://accounts.google.com", false},
		{"without a scheme", "", "accounts.google.com", false},
		{"with a path", "", g + "/x", false},
		{"with a leading space", "", " " + g, false},
		{"empty", "", "", false},
		{"a document issuer with a slash and the exact issuer", g + "/", g, true},
		{"a document issuer with a slash and the same", g + "/", g + "/", true},
		{"a document issuer with a slash and two slashes", g + "/", g + "//", false},
		{"a document issuer with a slash and three slashes", g + "/", g + "///", false},
		{"a document issuer with a slash and no scheme", g + "/", "accounts.google.com/", false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p, srv, _ := newGoogleEvents(t)
			if r.doc != "" {
				srv.SetRISCIssuer(r.doc)
			}
			c := tokenClaims(srv, eventTime, oneEvent("sessions-revoked", accountEvent("g-1")))
			c["iss"] = r.iss
			evs, err := p.ParseEvent(context.Background(), []byte(srv.RISCToken(c)))
			if !r.accept {
				if !errors.Is(err, provider.ErrInvalidEvent) {
					t.Fatalf("err = %v, want ErrInvalidEvent", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(evs) != 1 || evs[0].Subject != "g-1" {
				t.Errorf("events = %+v, want one event about g-1", evs)
			}
		})
	}
}

// The issuer inside an iss-sub subject is compared with the document's by the
// same rule: exact and one slash (both directions) have a subject; two slashes,
// another case of the host and no scheme do not, and the
// event is still returned, so that it is logged as an unknown subject.
// Covers: FR-48
func TestGoogleEventSubjectIssuerWithATrailingSlash(t *testing.T) {
	const g = mockidp.RISCIssuer
	rows := []struct {
		name string
		doc  string
		iss  any
		want string // the subject; "" for an unknown subject
	}{
		{"the exact issuer", "", g, "g-1"},
		{"one trailing slash", "", g + "/", "g-1"},
		{"two trailing slashes", "", g + "//", ""},
		{"an upper-case host", "", "https://Accounts.google.com", ""},
		{"an upper-case host with a slash", "", "https://Accounts.google.com/", ""},
		{"no scheme", "", "accounts.google.com", ""},
		{"empty", "", "", ""},
		{"a lone slash", "", "/", ""},
		{"the document's slash and the exact issuer", g + "/", g, "g-1"},
		{"the document's slash and the same", g + "/", g + "/", "g-1"},
		{"the document's slash and two", g + "/", g + "//", ""},
		{"the document's slash and three", g + "/", g + "///", ""},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p, srv, _ := newGoogleEvents(t)
			if r.doc != "" {
				srv.SetRISCIssuer(r.doc)
			}
			subject := map[string]any{"subject": map[string]any{"subject_type": "iss-sub", "iss": r.iss, "sub": "g-1"}}
			c := tokenClaims(srv, eventTime, oneEvent("sessions-revoked", subject))
			c["iss"] = r.doc
			if r.doc == "" {
				c["iss"] = g
			}
			evs, err := p.ParseEvent(context.Background(), []byte(srv.RISCToken(c)))
			if err != nil {
				t.Fatal(err)
			}
			if len(evs) != 1 || evs[0].Subject != r.want {
				t.Errorf("events = %+v, want one event with subject %q", evs, r.want)
			}
		})
	}
}
