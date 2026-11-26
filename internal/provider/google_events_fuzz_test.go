package provider

import (
	"encoding/json"
	"errors"
	"testing"
)

// FuzzGoogleSecurityEvents fuzzes the events claim of a security event token
// (SEC-39): no input panics, and every failure is ErrInvalidEvent.
// Covers: FR-48, SEC-39 (part)
// Acceptance: Google security events (part)
func FuzzGoogleSecurityEvents(f *testing.F) {
	const issuer = "https://accounts.google.com"
	for _, seed := range []string{
		`{"https://schemas.openid.net/secevent/risc/event-type/sessions-revoked":{"subject":{"subject_type":"iss-sub","iss":"https://accounts.google.com","sub":"g-1"}}}`,
		`{"https://schemas.openid.net/secevent/risc/event-type/verification":{"state":"check-1"}}`,
		`{"https://schemas.openid.net/secevent/oauth/event-type/token-revoked":{"subject":{"subject_type":"token"}}}`,
		`{}`,
		`"sessions-revoked"`,
		`null`,
		`[]`,
		`{"x":"y"}`,
		`{"x":{"subject":"g-1"}}`,
		`{"x":{"subject":{"subject_type":1}}}`,
		`{"x":{"subject":{"subject_type":"iss-sub","iss":"https://accounts.google.com","sub":""}}}`,
		`{"x":{"state":{}}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		evs, err := securityEvents(json.RawMessage(raw), issuer)
		if err != nil {
			if !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("error %v does not wrap ErrInvalidEvent", err)
			}
			return
		}
		for _, ev := range evs {
			if ev.Set != EventSetGoogle {
				t.Fatalf("event %+v has set %q, want google", ev, ev.Set)
			}
		}
	})
}
