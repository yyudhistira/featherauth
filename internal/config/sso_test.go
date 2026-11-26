package config

import (
	"strings"
	"testing"
	"time"
)

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
// The realm options sso.enabled, sso.idle_lifetime and sso.max_lifetime have
// the defaults of the design (false, 8h, 720h); both lifetimes must be greater
// than zero. A client's sso option is true unless it says false.
func TestSSOOptionsDefaultsAndRules(t *testing.T) {
	cases := []struct {
		name   string
		extra  string // realm options after the name
		field  string // the diagnostic's field; empty when the file is valid
		reason string
		enable bool
		idle   time.Duration
		max    time.Duration
	}{
		{name: "defaults", idle: 8 * time.Hour, max: 720 * time.Hour},
		{name: "enabled with lifetimes", extra: "sso:\n  enabled: true\n  idle_lifetime: 1h\n  max_lifetime: 2h\n",
			enable: true, idle: time.Hour, max: 2 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			y := realmHead + tc.extra + realmKeys + "clients:\n  web:\n    redirect_uris: [https://app.example.com/callback]\n"
			r, ds := DecodeRealm("realms/main.yaml", []byte(y))
			if len(ds) != 0 {
				t.Fatal(ds)
			}
			got := ValidateRealm("realms/main.yaml", r, RealmCheck{})
			if tc.field == "" {
				noErrors(t, got)
				if r.SSO.Enabled != tc.enable || r.SSO.IdleLifetime.Std() != tc.idle || r.SSO.MaxLifetime.Std() != tc.max {
					t.Fatalf("sso = %+v, want enabled %v, idle %s, max %s", r.SSO, tc.enable, tc.idle, tc.max)
				}
				return
			}
			if len(got) != 1 || got[0].File != "realms/main.yaml" || got[0].Field != tc.field || !strings.Contains(got[0].Message, tc.reason) {
				t.Fatalf("diagnostics %+v, want one for %s with %q", got, tc.field, tc.reason)
			}
		})
	}
}

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
func TestClientSSOOption(t *testing.T) {
	cases := []struct {
		name  string
		extra string
		want  bool
	}{
		{name: "default is true", want: true},
		{name: "false keeps the client out", extra: "    sso: false\n", want: false},
		{name: "true", extra: "    sso: true\n", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			y := realmHead + realmKeys + "clients:\n  web:\n    redirect_uris: [https://app.example.com/callback]\n" + tc.extra
			r, ds := DecodeRealm("realms/main.yaml", []byte(y))
			if len(ds) != 0 {
				t.Fatal(ds)
			}
			if got := r.Clients["web"].SSO; got != tc.want {
				t.Fatalf("client sso = %v, want %v", got, tc.want)
			}
		})
	}
}
