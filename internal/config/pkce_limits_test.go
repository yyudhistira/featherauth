package config

import (
	"strings"
	"testing"
)

// pkceRow is one case of the PKCE exception limits: a realm whose tokens and
// client are given, and the exact error messages it must produce (none when
// it is accepted). A warning is not listed; it is not what the rule decides.
type pkceRow struct {
	name   string
	tokens string // the realm's tokens block, "" for the defaults
	client string // the client's options, redirect_uris included
	want   []string
}

const (
	pkceIdleMsg    = "client web: a public client with require_pkce: false needs refresh_idle_lifetime of at most 24h"
	pkceSessionMsg = "client web: a public client with require_pkce: false needs session_max_lifetime above 0 and at most 720h"
	pkceURI        = "    redirect_uris: [https://app.example.com/cb]\n"
	pkcePublicOff  = "    require_pkce: false\n" + pkceURI
)

func pkceRows() []pkceRow {
	return []pkceRow{
		{name: "public client, 24 hours idle and 720 hours session",
			client: pkcePublicOff + "    refresh_idle_lifetime: 24h\n    session_max_lifetime: 720h\n"},
		{name: "public client, 24 hours and 1 second idle",
			client: pkcePublicOff + "    refresh_idle_lifetime: 24h1s\n    session_max_lifetime: 720h\n",
			want:   []string{pkceIdleMsg}},
		{name: "public client, 721 hours session",
			client: pkcePublicOff + "    refresh_idle_lifetime: 24h\n    session_max_lifetime: 721h\n",
			want:   []string{pkceSessionMsg}},
		{name: "public client, session of 0",
			client: pkcePublicOff + "    refresh_idle_lifetime: 24h\n    session_max_lifetime: 0s\n",
			want:   []string{pkceSessionMsg}},
		{name: "public client, idle inherited from the realm at 25 hours",
			tokens: "tokens:\n  refresh_idle_lifetime: 25h\n",
			client: pkcePublicOff + "    session_max_lifetime: 720h\n",
			want:   []string{pkceIdleMsg}},
		{name: "public client, idle inherited from the realm default of 720 hours",
			client: pkcePublicOff + "    session_max_lifetime: 720h\n",
			want:   []string{pkceIdleMsg}},
		{name: "public client, session of 0 inherited from the realm",
			tokens: "tokens:\n  session_max_lifetime: 0s\n",
			client: pkcePublicOff + "    refresh_idle_lifetime: 24h\n",
			want:   []string{pkceSessionMsg}},
		{name: "public client, session of 721 hours inherited from the realm",
			tokens: "tokens:\n  session_max_lifetime: 721h\n",
			client: pkcePublicOff + "    refresh_idle_lifetime: 24h\n",
			want:   []string{pkceSessionMsg}},
		{name: "public client, the client's own 30 minutes and 10 hours override the realm's long values",
			tokens: "tokens:\n  refresh_idle_lifetime: 17520h\n  session_max_lifetime: 0s\n",
			client: pkcePublicOff + "    refresh_idle_lifetime: 30m\n    session_max_lifetime: 10h\n"},
		{name: "public client, 30 minutes idle and 10 hours session set on the client",
			client: pkcePublicOff + "    refresh_idle_lifetime: 30m\n    session_max_lifetime: 10h\n"},
		{name: "public client, 24 hours idle and 720 hours session inherited from the realm",
			tokens: "tokens:\n  refresh_idle_lifetime: 24h\n  session_max_lifetime: 720h\n",
			client: pkcePublicOff},
		{name: "public client, 24 hours and 1 second idle inherited from the realm",
			tokens: "tokens:\n  refresh_idle_lifetime: 24h1s\n",
			client: pkcePublicOff + "    session_max_lifetime: 720h\n",
			want:   []string{pkceIdleMsg}},
		{name: "confidential client, 24 hours and 1 second idle, 721 hours session is not limited",
			client: "    type: confidential\n    client_secret_file: secrets/web\n    require_pkce: false\n" + pkceURI +
				"    refresh_idle_lifetime: 24h1s\n    session_max_lifetime: 721h\n"},
		{name: "public client with both limits broken reports both",
			client: pkcePublicOff,
			want:   []string{pkceIdleMsg, pkceSessionMsg}},
		{name: "a Keycloak-style public client: public client, 30 minutes idle and 10 hours session",
			tokens: "tokens:\n  refresh_idle_lifetime: 30m\n  session_max_lifetime: 10h\n",
			client: pkcePublicOff + "    response_mode: fragment\n"},
		{name: "confidential client is not limited",
			client: "    type: confidential\n    client_secret_file: secrets/web\n" + "    require_pkce: false\n" + pkceURI +
				"    refresh_idle_lifetime: 17520h\n    session_max_lifetime: 0s\n"},
		{name: "public client with PKCE is not limited",
			client: pkceURI + "    refresh_idle_lifetime: 17520h\n    session_max_lifetime: 0s\n"},
	}
}

// Covers: FR-32, SEC-01
// Acceptance: PKCE exception limits
func TestPKCEExceptionLimits(t *testing.T) {
	dir := keyDir(t)
	for _, tt := range pkceRows() {
		t.Run(tt.name, func(t *testing.T) {
			text := "name: main\n" + tt.tokens + realmKeys + "clients:\n  web:\n" + tt.client
			var errs []Diagnostic
			for _, d := range validateText(t, dir, "realm", "realms/main.yaml", text, false) {
				if d.Severity == Error {
					errs = append(errs, d)
				}
			}
			if len(errs) != len(tt.want) {
				t.Fatalf("want %d errors %q, got %v", len(tt.want), tt.want, errs)
			}
			line := 0
			if i := strings.Index(text, "    require_pkce: false"); i >= 0 {
				line = 1 + strings.Count(text[:i], "\n")
			}
			for i, d := range errs {
				if d.Message != tt.want[i] || d.File != "realms/main.yaml" || d.Field != "clients.web.require_pkce" || d.Line != line {
					t.Errorf("error %d: got %+v\nwant %q in realms/main.yaml line %d field clients.web.require_pkce", i, d, tt.want[i], line)
				}
			}
		})
	}
}
