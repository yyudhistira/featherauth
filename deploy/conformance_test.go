//go:build conformance

package deploy_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/testutil/configdir"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
)

// The conformance setup: FeatherAuth behind Caddy, the suite (release-v5.3.4)
// and a runner, from deploy/conformance/compose.yaml. The mock identity
// provider runs here, on the host, and the containers reach it as
// host.docker.internal. Results are exported to CONFORMANCE_OUT (default
// conformance-out in the repository).
const (
	confIssuerHost = "https://op.conformance.test"
	confRealm      = "conf"
	confAlias      = "featherauth"
	confSuiteURL   = "https://localhost.emobix.co.uk:8443"
)

const confServerYAML = `public_url: ` + confIssuerHost + `
listen: ":8080"
strict_permissions: false
rate_limit:
  per_ip_per_minute: 0
log_level: debug
secrets:
  encryption_key_files:
    - secrets/encryption_key
`

// The suite's static clients are confidential, authenticate with
// client_secret_basic and do not use PKCE (require_pkce is the only change from
// the defaults); each has the suite's callback and post-logout URIs.
const confRealmYAML = `name: ` + confRealm + `
sso:
  enabled: true
keys:
  - { kid: conf-1, file: secrets/signing.pem, state: active }
providers:
  sso:
    type: oidc
    enabled: true
    display_name: Mock SSO
    client_id: mock-client
    client_secret_file: secrets/sso_secret
    issuer: "%MOCK%"
clients:
  suite1:
    type: confidential
    client_secret_file: secrets/suite1_secret
    require_pkce: false
    redirect_uris: [` + confSuiteURL + `/test/a/` + confAlias + `/callback]
    post_logout_redirect_uris: [` + confSuiteURL + `/test/a/` + confAlias + `/post_logout_redirect]
  suite2:
    type: confidential
    client_secret_file: secrets/suite2_secret
    require_pkce: false
    redirect_uris: [` + confSuiteURL + `/test/a/` + confAlias + `/callback]
    post_logout_redirect_uris: [` + confSuiteURL + `/test/a/` + confAlias + `/post_logout_redirect]
`

func confSecret(t *testing.T, d *configdir.Dir, name string) string {
	t.Helper()
	d.Secret(t, "secrets/"+name)
	b, err := os.ReadFile(filepath.Join(d.Root, "secrets", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// The pages the suite's browser meets. Where FeatherAuth shows a page of its own
// (an error page or the signed-out page) the suite asks for a screenshot, which
// the browser step supplies by naming the page's text.
const (
	confErrorPage     = "Something went wrong"
	confSignedOutPage = "Signed out"
)

// confPlanConfig is the suite's configuration of the plans. The sign-in at the
// mock identity provider needs no page, so the browser only has to reach the
// suite's callback and post-logout pages. client_secret_post uses the same
// client as client: FeatherAuth accepts both authentication methods from a
// confidential client.
func confPlanConfig(c1, s1, c2, s2 string) map[string]any {
	op := confIssuerHost + "/" + confRealm
	wait := func(regexp, action string) []any {
		return []any{"wait", "xpath", "//*", 10, regexp, action}
	}
	login := func(extra ...[]any) map[string]any {
		cmds := append([][]any{{"wait", "id", "submission_complete", 10}}, extra...)
		return map[string]any{"match": op + "/authorize*", "tasks": []any{
			map[string]any{"task": "Verify Complete", "match": "*/test/*/callback*", "commands": cmds},
		}}
	}
	// the logout request ends on the suite's post-logout page, or on a page of
	// FeatherAuth's that holds text.
	logoutPage := func(task, text string) map[string]any {
		return map[string]any{"match": op + "/logout*", "tasks": []any{
			map[string]any{"task": task, "match": op + "/logout*", "commands": [][]any{wait(text, "update-image-placeholder")}},
		}}
	}
	errorPage := func() map[string]any {
		return map[string]any{"match": op + "/authorize*", "tasks": []any{
			map[string]any{"task": "Expect error page", "match": op + "/authorize*", "commands": [][]any{wait(confErrorPage, "update-image-placeholder")}},
		}}
	}
	override := func(b ...any) map[string]any { return map[string]any{"browser": b} }
	logoutFlow := func(last any) map[string]any { return override(login(), last) }
	return map[string]any{
		"alias":              confAlias,
		"description":        "FeatherAuth",
		"server":             map[string]any{"discoveryUrl": op + "/.well-known/openid-configuration"},
		"client":             map[string]any{"client_id": c1, "client_secret": s1},
		"client_secret_post": map[string]any{"client_id": c1, "client_secret": s1},
		"client2":            map[string]any{"client_id": c2, "client_secret": s2},
		"browser": []any{
			login(),
			map[string]any{"match": op + "/logout*", "tasks": []any{
				map[string]any{"task": "Verify Complete", "match": "*/test/*/post_logout_redirect*"},
			}},
		},
		"override": map[string]any{
			// FeatherAuth has no login page, so the screenshot the suite asks for
			// is of the page the browser ends on.
			"oidcc-prompt-login":                                                override(login([]any{"wait", "xpath", "//*", 10, ".*", "update-image-placeholder-optional"})),
			"oidcc-max-age-1":                                                   override(login([]any{"wait", "xpath", "//*", 10, ".*", "update-image-placeholder-optional"})),
			"oidcc-ensure-registered-redirect-uri":                              override(errorPage()),
			"oidcc-ensure-request-object-with-redirect-uri":                     override(errorPage()),
			"oidcc-rp-initiated-logout-bad-post-logout-redirect-uri":            logoutFlow(logoutPage("Expect error page", confErrorPage)),
			"oidcc-rp-initiated-logout-modified-id-token-hint":                  logoutFlow(logoutPage("Expect error page", confErrorPage)),
			"oidcc-rp-initiated-logout-bad-id-token-hint":                       logoutFlow(logoutPage("Expect error page", confErrorPage)),
			"oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri": logoutFlow(logoutPage("Expect error page", confErrorPage)),
			"oidcc-rp-initiated-logout-no-id-token-hint":                        logoutFlow(logoutPage("Expect signed-out page", confSignedOutPage)),
			"oidcc-rp-initiated-logout-no-params":                               logoutFlow(logoutPage("Expect signed-out page", confSignedOutPage)),
			"oidcc-rp-initiated-logout-only-state":                              logoutFlow(logoutPage("Expect signed-out page", confSignedOutPage)),
			"oidcc-rp-initiated-logout-no-post-logout-redirect-uri":             logoutFlow(logoutPage("Expect signed-out page", confSignedOutPage)),
		},
	}
}

func confRun(t *testing.T, env []string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "docker", append([]string{"compose", "-f", "deploy/conformance/compose.yaml"}, args...)...)
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	t.Logf("docker compose %s:\n%s", strings.Join(args, " "), out)
	if err != nil {
		t.Fatalf("docker compose %s: %v", strings.Join(args, " "), err)
	}
}

// Covers: FR-01, FR-02, FR-06, FR-07, FR-08, FR-09, FR-10, FR-11
// Acceptance: OpenID conformance suite
//
// The conditions of the row and the test that asserts each:
//   - the Basic OP, Config OP and RP-Initiated Logout OP plans run against a
//     test realm with a static client of each plan, discovery, and a generic
//     oidc provider pointing at the mock identity provider: this test, through
//     deploy/conformance/run-plans.sh (run-test-plan.py exits non-zero on any
//     failure or warning that is not listed);
//   - every test passes, or its warning or failure is recorded with the reason
//     in the conformance section of docs/RESULTS.md: deploy/conformance/expected/<plan>-failures.json
//     and <plan>-skips.json list exactly the recorded ones, and run-plans.sh
//     fails on any other or on a listed one that does not happen, so this test
//     fails unless each is either passing or listed;
//   - the protocol conditions of FR-06 to FR-11 that the suite exercises are
//     asserted one by one by tests tagged "(part)" (the suite shows the
//     endpoints interoperate; these assert each condition):
//     FR-06 (response modes): oidc TestCallbackDeliversTheCodeInEveryResponseMode,
//     TestDeliverPutsEveryValueInTheRightPlace;
//     FR-07 (code grant): PKCE downgrade rejection oidc TestTokenPKCEDowngrade,
//     TestTokenPKCE; disabled user or removed client gives invalid_grant token
//     TestCodeGrantStateChangedAfterIssue; code reuse revokes the session oidc
//     TestTokenCodeLifetimeAndReuse; client authentication oidc
//     TestTokenClientAuthentication;
//     FR-08 (refresh): rotation per client type: public client oidc
//     TestTokenRefreshRotation, confidential client with rotation off
//     TestTokenRotationOff; grace window oidc TestTokenRefreshWithinGrace,
//     TestRefreshReplayAfterTheGraceWindow;
//     FR-09 (userinfo): GET and POST, invalid token oidc
//     TestUserinfoGetAndPostGiveTheSameClaims, TestUserinfoInvalidTokenAndMethods;
//     FR-10 (JWKS): oidc TestJWKSServesEveryKeyWithUseAlgKidAndCacheHeader;
//     FR-11 (logout): oidc TestLogoutByHint, TestLogoutRefusals,
//     TestLogoutWithoutHint;
//   - the results file carries the date, the commit and the suite version:
//     TestConformanceResultsRecordSuiteVersion.
func TestConformanceSuite(t *testing.T) {
	out := os.Getenv("CONFORMANCE_OUT")
	if out == "" {
		out = filepath.Join("..", "conformance-out")
	}
	out, err := filepath.Abs(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}

	// The mock listens on all interfaces so the containers can reach it as
	// host.docker.internal. It is a test double with its secret check off, run
	// for the length of this test on a development machine or a CI runner; that
	// exposure is accepted.
	mock := mockidp.ListenAt(t, clock.Real(), mockidp.Generic, "0.0.0.0:0", "")
	_, port, err := net.SplitHostPort(mock.Addr())
	if err != nil {
		t.Fatal(err)
	}
	mock.SetPublicURL("http://host.docker.internal:" + port)
	mock.SetUser(mockidp.User{Sub: "conformance-user", Name: "Conformance User", Email: "conformance@example.com", EmailVerified: true})
	mock.SetSession(true)
	mock.SetSecretCheck(func(string) error { return nil })
	mock.SetCredentials("mock-client", "unused")

	d := configdir.New(t)
	d.Server(t, confServerYAML)
	d.RSAKey(t, "secrets/signing.pem")
	d.EncryptionKey(t, "secrets/encryption_key")
	d.Secret(t, "secrets/sso_secret")
	s1 := confSecret(t, d, "suite1_secret")
	s2 := confSecret(t, d, "suite2_secret")
	d.Realm(t, confRealm, strings.ReplaceAll(confRealmYAML, "%MOCK%", mock.URL()))
	openPermissions(t, d.Root)

	cfg, err := json.MarshalIndent(confPlanConfig("suite1", s1, "suite2", s2), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "plan-config.json"), cfg, 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{"CONFORMANCE_CONFIG=" + d.Root, "CONFORMANCE_OUT=" + out}
	t.Cleanup(func() { confRun(t, env, "--profile", "run", "down", "--volumes", "--remove-orphans") })
	confRun(t, env, "up", "--build", "--detach", "--wait")
	confRun(t, env, "run", "--rm", "--build", "runner")
}
