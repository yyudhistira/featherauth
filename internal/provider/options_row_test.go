package provider

import (
	"bytes"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/logx"
	"github.com/yyudhistira/featherauth/internal/testutil"
)

// The row "Provider options" asks for a test of every option of the two provider
// tables of the Configuration reference, with a value other than the default.
// This file reads the tables from docs/DESIGN.md, so an option added to the
// design with no case here fails the test.
//
// Each option has a proof: a case in this file that sets the option in a realm
// file and reads what the registry builds from it (the authorize URL of the
// adapter it returns, or the options it passes to the adapter), and/or the tests
// that prove its effect where the adapter or the service applies it (the
// adapter contract and option tests, the user tests, the full flows). A named
// test must exist, so a renamed test fails here too.

// optionTables returns the options of the two provider tables of the design as
// "common/<option>" and "<type>/<option>".
func optionTables(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/DESIGN.md")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	table := ""
	for _, l := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(l, "Common options for every provider"):
			table = "common"
			continue
		case strings.HasPrefix(l, "Per-provider options and defaults"):
			table = "per-provider"
			continue
		case table == "":
			continue
		case !strings.HasPrefix(l, "|"):
			if l != "" {
				table = ""
			}
			continue
		}
		cells := strings.Split(strings.Trim(l, "|"), " | ")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if cells[0] == "Option" || cells[0] == "Provider" || strings.HasPrefix(cells[0], "---") {
			continue
		}
		scope, cell := "common", cells[0]
		if table == "per-provider" {
			scope, cell = strings.ToLower(strings.Trim(cells[0], "`")), cells[1]
		}
		prefix := ""
		for _, part := range strings.Split(cell, ",") {
			p := strings.Trim(strings.TrimSpace(part), "`")
			if strings.HasPrefix(p, ".") {
				p = prefix + p
			} else if i := strings.LastIndex(p, "."); i >= 0 {
				prefix = p[:i]
			}
			out = append(out, scope+"/"+p)
		}
	}
	return out
}

// optionsRealm sets every option of the tables to a value other than its
// default.
const optionsRealm = `  google:
    enabled: true
    display_name: Work Google
    hidden: true
    client_id: g-opt
    client_secret_file: secrets/main/google_secret
    scopes: [openid, email]
    trust_email: false
    auto_link: false
    sync_mode: force
    timeout: 3s
    hosted_domain: acme.example
    endpoints: {authorize: "http://127.0.0.1:9/ga", token: "http://127.0.0.1:9/gt", jwks: "http://127.0.0.1:9/gj", userinfo: "http://127.0.0.1:9/gu", risc_configuration: "http://127.0.0.1:9/risc"}
  apple:
    enabled: true
    client_id: com.example.opt
    team_id: TEAM000001
    key_id: KEY0000001
    private_key_file: secrets/main/apple.p8
    client_secret_lifetime: 7m
    store_refresh_token: false
    scopes: [email]
    trust_email: false
    notification_audiences: [com.example.other]
    timeout: 4s
    endpoints: {authorize: "http://127.0.0.1:9/aa", token: "http://127.0.0.1:9/at", jwks: "http://127.0.0.1:9/aj"}
  github:
    enabled: true
    client_id: gh-opt
    client_secret_file: secrets/main/github_secret
    scopes: [user:email]
    pkce: false
    allow_signup: false
    require_verified_email: false
    trust_email: false
    timeout: 5s
    endpoints: {authorize: "http://127.0.0.1:9/ha", token: "http://127.0.0.1:9/ht", userinfo: "http://127.0.0.1:9/hu"}
  facebook:
    enabled: true
    client_id: fb-opt
    client_secret_file: secrets/main/facebook_secret
    graph_version: v19.0
    flow: oauth
    scopes: [email]
    fields: [email]
    require_email: true
    trust_email: true
    timeout: 6s
    endpoints: {authorize: "http://127.0.0.1:9/fa", token: "http://127.0.0.1:9/ft", userinfo: "http://127.0.0.1:9/fu"}
  corp:
    type: oidc
    enabled: true
    client_id: c-opt
    client_secret_file: secrets/main/corp_secret
    issuer: "http://127.0.0.1:9/corp"
    scopes: [email]
    trust_email: true
    timeout: 2s
    endpoints: {authorize: "http://127.0.0.1:9/ca", token: "http://127.0.0.1:9/ct", jwks: "http://127.0.0.1:9/cj", userinfo: "http://127.0.0.1:9/cu"}
`

// optionsFixture is the realm of optionsRealm, loaded, with the adapters its
// registry builds.
type optionsFixture struct {
	t     *testing.T
	realm *config.Realm
	spec  map[string]spec
	pool  *Pool
	dir   string
}

func newOptionsFixture(t *testing.T) *optionsFixture {
	t.Helper()
	l, d := testutil.NewProviderConfig(t, optionsRealm, "google", "github", "facebook", "corp")
	snap := l.Current()
	r, ok := snap.Realm("main")
	if !ok {
		t.Fatal("no realm main")
	}
	clk := clock.NewFake(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	f := &optionsFixture{t: t, realm: r, spec: map[string]spec{}, pool: NewPool(l, clk, logx.New(&bytes.Buffer{}, slog.LevelDebug, clk)), dir: d.Root}
	for _, k := range []string{"google", "apple", "github", "facebook", "corp"} {
		sp, err := newSpec(clk, r, config.ProviderKey(k), r.Providers[config.ProviderKey(k)], snap.Secrets())
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		f.spec[k] = sp
	}
	return f
}

// auth returns the authorize URL of the adapter the registry builds for key.
func (f *optionsFixture) auth(key string) *url.URL {
	f.t.Helper()
	p, ok := f.pool.Get("main", config.ProviderKey(key))
	if !ok {
		f.t.Fatalf("the registry has no adapter for %s", key)
	}
	u, err := url.Parse(p.AuthURL("st", "nonce", "chal", AuthOptions{}))
	if err != nil {
		f.t.Fatal(err)
	}
	return u
}

// base is an authorize URL without its query.
func base(u *url.URL) string { return u.Scheme + "://" + u.Host + u.Path }

// secretFile is what the file named by client_secret_file holds.
func (f *optionsFixture) secretFile(key string) string {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "secrets", "main", key+"_secret"))
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// optionsProof is how one option is proved: the case in this file, and the
// tests (by name, in any package) that prove the effect the adapter or the
// service gives it.
type optionsProof struct {
	tests []string
	run   func(t *testing.T, f *optionsFixture)
}

func eq[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

// scopeOf is the scope parameter of the authorize URL of key.
func (f *optionsFixture) scopeOf(key string) string { return f.auth(key).Query().Get("scope") }

// optionProofs is the table of the proofs.
func optionProofs() map[string]optionsProof {
	clientID := func(key, want string) func(*testing.T, *optionsFixture) {
		return func(t *testing.T, f *optionsFixture) {
			eq(t, key+" client_id", f.auth(key).Query().Get("client_id"), want)
		}
	}
	return map[string]optionsProof{
		"common/type": {tests: []string{"TestRegistryBuildsAdaptersFromConfig"}, run: func(t *testing.T, f *optionsFixture) {
			for k, want := range map[string]string{"google": "google", "apple": "apple", "github": "github", "facebook": "facebook", "corp": "oidc"} {
				eq(t, k+" kind", f.spec[k].kind, want)
			}
		}},
		"common/enabled": {tests: []string{"TestRegistryBuildsAdaptersFromConfig", "TestRegistryVisibleExcludesHiddenAndDisabledInOrder"}},
		"common/display_name": {tests: []string{"TestChooserOrder", "TestChooseProvider"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "display_name", f.realm.Providers["google"].DisplayName, "Work Google")
		}},
		"common/hidden": {tests: []string{"TestRegistryVisibleExcludesHiddenAndDisabledInOrder", "TestChooseProvider"}, run: func(t *testing.T, f *optionsFixture) {
			if v := f.pool.Visible("main"); slices.Contains(v, config.ProviderKey("google")) || !slices.Contains(v, config.ProviderKey("github")) {
				t.Errorf("visible providers %v: the hidden google is listed, or github is not", v)
			}
			if _, ok := f.pool.Get("main", "google"); !ok {
				t.Error("a hidden provider has no adapter: its hint would not work")
			}
		}},
		"common/client_id": {run: func(t *testing.T, f *optionsFixture) {
			for k, want := range map[string]string{"google": "g-opt", "apple": "com.example.opt", "github": "gh-opt", "facebook": "fb-opt", "corp": "c-opt"} {
				clientID(k, want)(t, f)
			}
		}},
		"common/client_secret_file": {tests: []string{"TestFacebookGraphCallsCarryTheAppSecretProof"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "google secret", f.spec["google"].google.ClientSecret, f.secretFile("google"))
			eq(t, "github secret", f.spec["github"].github.ClientSecret, f.secretFile("github"))
			eq(t, "facebook secret", f.spec["facebook"].facebook.ClientSecret, f.secretFile("facebook"))
			eq(t, "corp secret", f.spec["corp"].oidc.ClientSecret, f.secretFile("corp"))
		}},
		"common/scopes": {run: func(t *testing.T, f *optionsFixture) {
			eq(t, "google scope", f.scopeOf("google"), "openid email")
			eq(t, "github scope", f.scopeOf("github"), "user:email")
			eq(t, "facebook scope", f.scopeOf("facebook"), "email")
			eq(t, "corp scope", f.scopeOf("corp"), "openid email")
		}},
		"common/trust_email": {tests: []string{"TestTrustEmailOptionEndToEnd", "TestNoUnsafeLinkEndToEnd"}},
		"common/auto_link":   {tests: []string{"TestOneVerifiedEmailEndToEnd", "TestAutoLinkEndToEnd", "TestAutoLinkGoogleThenApple"}},
		"common/sync_mode":   {tests: []string{"TestEmailChangeEndToEnd", "TestEmailChangeBySyncMode"}},
		"common/timeout": {tests: []string{"TestGitHubAPITimeoutIsUnavailable", "TestOIDCNeedsAPositiveTimeout"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "google timeout", f.spec["google"].google.Timeout, 3*time.Second)
			eq(t, "apple timeout", f.spec["apple"].apple.Timeout, 4*time.Second)
			eq(t, "github timeout", f.spec["github"].github.Timeout, 5*time.Second)
			eq(t, "facebook timeout", f.spec["facebook"].facebook.Timeout, 6*time.Second)
			eq(t, "corp timeout", f.spec["corp"].oidc.Timeout, 2*time.Second)
		}},
		"common/endpoints.authorize": {tests: []string{"TestOIDCEndpointOverridesNeedNoDiscovery"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "google", base(f.auth("google")), "http://127.0.0.1:9/ga")
			eq(t, "apple", base(f.auth("apple")), "http://127.0.0.1:9/aa")
			eq(t, "github", base(f.auth("github")), "http://127.0.0.1:9/ha")
			eq(t, "facebook", base(f.auth("facebook")), "http://127.0.0.1:9/fa")
			eq(t, "corp", base(f.auth("corp")), "http://127.0.0.1:9/ca")
		}},
		"common/endpoints.token": {tests: []string{"TestOIDCEndpointOverridesNeedNoDiscovery"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "google", f.spec["google"].google.Endpoints.Token, "http://127.0.0.1:9/gt")
			eq(t, "apple", f.spec["apple"].apple.Endpoints.Token, "http://127.0.0.1:9/at")
			eq(t, "github", f.spec["github"].github.TokenURL, "http://127.0.0.1:9/ht")
			eq(t, "facebook", f.spec["facebook"].facebook.TokenURL, "http://127.0.0.1:9/ft")
			eq(t, "corp", f.spec["corp"].oidc.Endpoints.Token, "http://127.0.0.1:9/ct")
		}},
		"common/endpoints.userinfo": {tests: []string{"TestGoogleCallsUserinfoWhenSet", "TestOIDCUserinfoFillsMissingClaims", "TestGitHubUserURLReplacesOnlyTheUserCall", "TestFacebookMeURLReplacesTheIdentityCall", "TestAppleIgnoresTheUserinfoEndpoint"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "google", f.spec["google"].google.Endpoints.Userinfo, "http://127.0.0.1:9/gu")
			eq(t, "github", f.spec["github"].github.UserURL, "http://127.0.0.1:9/hu")
			eq(t, "facebook", f.spec["facebook"].facebook.MeURL, "http://127.0.0.1:9/fu")
			eq(t, "corp", f.spec["corp"].oidc.Endpoints.Userinfo, "http://127.0.0.1:9/cu")
		}},
		"common/endpoints.jwks": {tests: []string{"TestOIDCEndpointOverridesNeedNoDiscovery"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "google", f.spec["google"].google.Endpoints.JWKS, "http://127.0.0.1:9/gj")
			eq(t, "apple", f.spec["apple"].apple.Endpoints.JWKS, "http://127.0.0.1:9/aj")
			eq(t, "corp", f.spec["corp"].oidc.Endpoints.JWKS, "http://127.0.0.1:9/cj")
		}},

		"google/scopes":      {run: func(t *testing.T, f *optionsFixture) { eq(t, "scope", f.scopeOf("google"), "openid email") }},
		"google/trust_email": {tests: []string{"TestTrustEmailOptionEndToEnd"}},
		"google/hosted_domain": {tests: []string{"TestGoogleHostedDomain"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "hd", f.auth("google").Query().Get("hd"), "acme.example")
		}},
		"google/endpoints.risc_configuration": {tests: []string{"TestGoogleRISCDocumentWithoutIssuerOrKeysIsUnavailable", "TestGoogleEventTypesOfTheTable"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "RISC configuration", f.spec["google"].google.RISCConfigurationURL, "http://127.0.0.1:9/risc")
		}},

		"apple/client_id": {run: clientID("apple", "com.example.opt")},
		"apple/team_id":   {tests: []string{"TestAppleGeneratesTheClientSecretPerRequest"}, run: func(t *testing.T, f *optionsFixture) { eq(t, "team_id", f.spec["apple"].apple.TeamID, "TEAM000001") }},
		"apple/key_id":    {tests: []string{"TestAppleGeneratesTheClientSecretPerRequest"}, run: func(t *testing.T, f *optionsFixture) { eq(t, "key_id", f.spec["apple"].apple.KeyID, "KEY0000001") }},
		"apple/private_key_file": {tests: []string{"TestAppleGeneratesTheClientSecretPerRequest"}, run: func(t *testing.T, f *optionsFixture) {
			if len(f.spec["apple"].apple.PrivateKeyPEM) == 0 {
				t.Error("the Apple key of the file did not reach the adapter")
			}
		}},
		"apple/client_secret_lifetime": {tests: []string{"TestAppleGeneratesTheClientSecretPerRequest"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "lifetime", f.spec["apple"].apple.Lifetime, 7*time.Minute)
		}},
		"apple/store_refresh_token": {tests: []string{"TestAppleRefreshTokenOnlyWhenStored", "TestAppleLoginWithoutStoreRefreshTokenStoresNothing"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "store_refresh_token", f.spec["apple"].apple.StoreRefreshToken, false)
		}},
		"apple/scopes": {tests: []string{"TestAppleScopesInTheAuthorizeURL"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "scope", f.scopeOf("apple"), "email")
			eq(t, "response_mode", f.auth("apple").Query().Get("response_mode"), "form_post")
		}},
		"apple/trust_email": {tests: []string{"TestTrustEmailOptionEndToEnd"}},
		"apple/notification_audiences": {tests: []string{"TestAppleParseEventAudience", "TestAppleEventNotificationAudience"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "audiences", strings.Join(f.spec["apple"].apple.NotificationAudiences, ","), "com.example.other")
		}},

		"github/scopes": {run: func(t *testing.T, f *optionsFixture) { eq(t, "scope", f.scopeOf("github"), "user:email") }},
		"github/pkce": {tests: []string{"TestGitHubAuthURLOptions"}, run: func(t *testing.T, f *optionsFixture) {
			if q := f.auth("github").Query(); q.Has("code_challenge") || q.Has("code_challenge_method") {
				t.Errorf("pkce false still sends a challenge: %v", q)
			}
		}},
		"github/allow_signup": {tests: []string{"TestGitHubAuthURLOptions", "TestRegistryBuildsAdaptersFromConfig"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "allow_signup", f.auth("github").Query().Get("allow_signup"), "false")
		}},
		"github/require_verified_email": {tests: []string{"TestGitHubVerifiedEmailRules"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "require_verified_email", f.spec["github"].github.RequireVerifiedEmail, false)
		}},
		"github/trust_email": {tests: []string{"TestTrustEmailOptionEndToEnd"}},

		"facebook/graph_version": {tests: []string{"TestRegistryBuildsAdaptersFromConfig"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "graph_version", f.spec["facebook"].facebook.GraphVersion, "v19.0")
		}},
		"facebook/flow":   {tests: []string{"TestSpecErrors", "TestValidationRulesReportFileLineFieldAndReason"}},
		"facebook/scopes": {run: func(t *testing.T, f *optionsFixture) { eq(t, "scope", f.scopeOf("facebook"), "email") }},
		"facebook/fields": {tests: []string{"TestFacebookFieldsAlwaysIncludeID"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "fields", strings.Join(f.spec["facebook"].facebook.Fields, ","), "email")
		}},
		"facebook/require_email": {tests: []string{"TestFacebookRequireEmail"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "require_email", f.spec["facebook"].facebook.RequireEmail, true)
		}},
		"facebook/trust_email": {tests: []string{"TestFacebookTrustEmailDefaultsToFalse", "TestValidationRulesReportFileLineFieldAndReason", "TestTrustEmailOptionEndToEnd"}},

		"oidc/issuer": {tests: []string{"TestRegistryDiscoveryDownStaysListedAndRetriesEveryThirtySeconds"}, run: func(t *testing.T, f *optionsFixture) {
			eq(t, "issuer", f.spec["corp"].oidc.Issuer, "http://127.0.0.1:9/corp")
		}},
		"oidc/scopes":      {run: func(t *testing.T, f *optionsFixture) { eq(t, "scope", f.scopeOf("corp"), "openid email") }},
		"oidc/trust_email": {tests: []string{"TestTrustEmailOptionEndToEnd", "TestOIDCTrustEmailDefaultsToFalse"}},
	}
}

// optionGaps are documented options with no proof of their effect, each with
// the reason; the test lists them, and the row's pending entry stays. None is
// left: Apple's scopes have their proof (FR-56).
var optionGaps = map[string]string{}

// testFunctions returns the names of the test functions of the repository.
func testFunctions(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, dir := range []string{"../../internal", "../../cmd"} {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, l := range strings.Split(string(b), "\n") {
				if rest, ok := strings.CutPrefix(l, "func Test"); ok {
					if i := strings.Index(rest, "("); i > 0 {
						names["Test"+rest[:i]] = true
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return names
}

// Every option of the provider tables of the design has a proof, and each
// proof holds with the option set to a value other than its default.
//
// Covers: FR-56
// Acceptance: Provider options
func TestProviderOptionsEveryOptionHasAProof(t *testing.T) {
	documented := optionTables(t)
	if len(documented) < 40 {
		t.Fatalf("the test read only %d options from the design", len(documented))
	}
	proofs := optionProofs()
	functions := testFunctions(t)
	f := newOptionsFixture(t)
	seen := map[string]bool{}
	for _, key := range documented {
		seen[key] = true
		if reason, ok := optionGaps[key]; ok {
			t.Logf("no proof for %s: %s", key, reason)
			continue
		}
		pr, ok := proofs[key]
		if !ok {
			t.Errorf("the option %s of the design has no proof; add it to optionProofs", key)
			continue
		}
		if pr.run == nil && len(pr.tests) == 0 {
			t.Errorf("the proof of %s names no case and no test", key)
		}
		for _, name := range pr.tests {
			if !functions[name] {
				t.Errorf("the proof of %s names %s, which is not a test of the repository", key, name)
			}
		}
		if pr.run != nil {
			t.Run(key, func(t *testing.T) { pr.run(t, f) })
		}
	}
	for key := range proofs {
		if !seen[key] {
			t.Errorf("optionProofs has %s, which the provider tables of the design do not list", key)
		}
	}
	for key := range optionGaps {
		if !seen[key] {
			t.Errorf("optionGaps has %s, which the provider tables of the design do not list", key)
		}
	}
}
