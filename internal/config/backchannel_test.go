package config

import (
	"fmt"
	"strings"
	"testing"
)

// Covers: FR-43 (part)
// Acceptance: Back-channel logout (part)
// backchannel_logout_uri is empty, or an absolute https URL without a fragment;
// http is accepted only with require_https: false (SEC-35).
func TestBackchannelLogoutURIRules(t *testing.T) {
	cases := []struct {
		name   string
		uri    string
		httpOK bool   // require_https: false
		reason string // a part of the diagnostic; empty when the file is valid
	}{
		{name: "https", uri: "https://app.example.com/logout"},
		{name: "empty turns it off", uri: ""},
		{name: "http with require_https false", uri: "http://127.0.0.1:8080/logout", httpOK: true},
		{name: "http with require_https true", uri: "http://app.example.com/logout", reason: "require_https is true"},
		{name: "fragment", uri: "https://app.example.com/logout#top", reason: "no fragment"},
		{name: "no host", uri: "https:///logout", reason: "no fragment"},
		{name: "other scheme", uri: "ftp://app.example.com/logout", reason: "https"},
		{name: "not an absolute URL", uri: "app.example.com/logout", reason: "https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := defaultServer()
			srv.RequireHTTPS = !tc.httpOK
			y := realmHead + fmt.Sprintf("clients:\n  web:\n    redirect_uris: [https://app.example.com/callback]\n    backchannel_logout_uri: %q\n", tc.uri) + realmKeys
			r, ds := DecodeRealm("realms/main.yaml", []byte(y))
			if len(ds) != 0 {
				t.Fatal(ds)
			}
			got := ValidateRealm("realms/main.yaml", r, RealmCheck{Server: &srv})
			if tc.reason == "" {
				noErrors(t, got)
				return
			}
			if len(got) != 1 || got[0].Field != "clients.web.backchannel_logout_uri" || !strings.Contains(got[0].Message, tc.reason) {
				t.Fatalf("diagnostics %+v, want one for clients.web.backchannel_logout_uri with %q", got, tc.reason)
			}
		})
	}
}
