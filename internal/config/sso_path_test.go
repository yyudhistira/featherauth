package config_test

import (
	"testing"

	"github.com/yyudhistira/featherauth/internal/config"
)

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on start (part)
// The browser session cookie's path is the longest common directory of the
// realm's authorize and logout paths (SEC-37): it reaches both and nothing
// wider than needed.
func TestSSOCookiePathIsTheCommonDirectory(t *testing.T) {
	cases := []struct {
		name   string
		server string
		want   string
	}{
		{"default layout", "", "/main"},
		{"auth prefix", "urls:\n  path_prefix: /auth\n", "/auth/main"},
		{"keycloak-style layout", keycloakURLs, "/auth/realms/main/protocol/openid-connect"},
		{"different directories share only the root", "urls:\n  endpoints:\n    authorize: \"/x/{realm}/authorize\"\n    logout: \"/y/{realm}/logout\"\n", "/"},
		{"logout below a sibling directory", "urls:\n  endpoints:\n    authorize: \"/x/{realm}/a/authorize\"\n    logout: \"/x/{realm}/b/logout\"\n", "/x/main"},
		{"logout below the authorize path", "urls:\n  endpoints:\n    authorize: \"/x/{realm}/authorize\"\n    logout: \"/x/{realm}/authorize/logout\"\n", "/x/main"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := config.NewSnapshot(decodeServer(t, tc.server), nil, []*config.RealmFile{decodeRealm(t, realmYAML)}, nil)
			r, ok := snap.Realm("main")
			if !ok {
				t.Fatal("realm main missing")
			}
			if got := r.SSOCookiePath(); got != tc.want {
				t.Errorf("SSOCookiePath = %q, want %q (authorize %q, logout %q)", got, tc.want,
					r.EndpointPath(config.EndpointAuthorize, ""), r.EndpointPath(config.EndpointLogout, ""))
			}
		})
	}
}
