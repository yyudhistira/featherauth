package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/testutil/logscan"
	"github.com/yyudhistira/featherauth/internal/testutil/mockidp"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// The steps of the emergency key rotation (section 8 of docs/USER_GUIDE.md) run against
// the real service: the configuration files, the CLI and the HTTP endpoints.
// The fake clock and the mock identity providers are the only fakes. The same
// file holds the wiring test of the security fixes: one login per provider, a
// refresh, and the fixes once more through the service, ending with the scan
// of the logs for secrets.

const (
	guidePath      = "../../docs/USER_GUIDE.md"
	runbookHeading = "8. Emergency key rotation"
)

// readRunbook returns the text of the emergency key rotation chapter of the
// user guide (section 8, up to the next chapter), which the tests read from
// the repository.
func readRunbook(t testing.TB) string {
	t.Helper()
	b, err := os.ReadFile(guidePath)
	if err != nil {
		t.Fatalf("the user guide is missing: %v", err)
	}
	return section(t, string(b), "## ", runbookHeading)
}

// runbookCommand matches a featherauth command named in the runbook: the
// word after "featherauth" and, when present, the word after that.
var runbookCommand = regexp.MustCompile(`featherauth ([a-z]+)(?: ([a-z-]+))?`)

var (
	codeSpan     = regexp.MustCompile("`([^`\\n]+)`")
	guideRunLine = regexp.MustCompile(`(?:^|\s)run ([a-z]+(?: .*)?)$`)
	guideBinary  = regexp.MustCompile(`/featherauth ([a-z]+(?: .*)?)$`)
)

// guideCommands returns the featherauth commands the chapter names, each as
// "featherauth <name> <args>" so that missingCommands can check them. The guide
// writes a command in one of three ways, in a code span or a code block: as
// "run <command>" (the one-off container of 3.2), after "/featherauth" (the
// running container), or as the bare command ("session revoke <realm> --all"),
// which counts when its first word is a command name of the table.
func guideCommands(text string, table map[string][]string) []string {
	var found []string
	add := func(candidate string) {
		if m := guideRunLine.FindStringSubmatch(candidate); m != nil {
			found = append(found, "featherauth "+m[1])
		} else if m := guideBinary.FindStringSubmatch(candidate); m != nil {
			found = append(found, "featherauth "+m[1])
		} else if w := strings.Fields(candidate); len(w) > 0 {
			if _, ok := table[w[0]]; ok {
				found = append(found, "featherauth "+candidate)
			}
		}
	}
	inFence := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			add(strings.TrimSpace(line))
			continue
		}
		for _, m := range codeSpan.FindAllStringSubmatch(line, -1) {
			add(m[1])
		}
	}
	return found
}

// commandNames splits the command list of the usage text: a line of the list
// starts with two spaces and the name of a command, and the words that follow
// the name, before the description column (two spaces), are its arguments; a
// command with subcommands lists them as the first argument, separated by "|"
// (user get|list|...).
func commandNames(usageText string) map[string][]string {
	subcommands := regexp.MustCompile(`^[a-z-]+(\|[a-z-]+)*$`)
	columns := regexp.MustCompile(`\s{2,}`)
	table := map[string][]string{}
	inList := false
	for _, line := range strings.Split(usageText, "\n") {
		if line == "commands:" {
			inList = true
			continue
		}
		if !inList || !strings.HasPrefix(line, "  ") || len(line) < 3 || line[2] == ' ' {
			continue // not a line of the list; a continuation line is indented further
		}
		left := columns.Split(strings.TrimSpace(line), 2)[0]
		words := strings.Fields(left)
		var subs []string
		if len(words) > 1 && subcommands.MatchString(words[1]) {
			subs = strings.Split(words[1], "|")
		}
		if _, ok := table[words[0]]; !ok {
			table[words[0]] = nil
		}
		for _, s := range subs {
			if !slices.Contains(table[words[0]], s) {
				table[words[0]] = append(table[words[0]], s)
			}
		}
	}
	return table
}

// missingCommands returns the featherauth commands of text that the table does
// not have: an unknown name, or a subcommand that is not listed under its name.
func missingCommands(text string, table map[string][]string) []string {
	var missing []string
	for _, m := range runbookCommand.FindAllStringSubmatch(text, -1) {
		name, sub := m[1], m[2]
		subs, ok := table[name]
		switch {
		case !ok:
			missing = append(missing, "featherauth "+name)
		case len(subs) > 0 && !slices.Contains(subs, sub):
			missing = append(missing, "featherauth "+name+" "+sub)
		}
	}
	return missing
}

// section returns the text under a heading ("## " or "### " is the level
// prefix) up to the next heading of that level.
func section(t testing.TB, text, level, heading string) string {
	t.Helper()
	_, rest, ok := strings.Cut(text, "\n"+level+heading+"\n")
	if !ok {
		t.Fatalf("the user guide has no heading %q", level+heading)
	}
	body, _, _ := strings.Cut(rest, "\n"+level)
	return body
}

// checkRunbookCommands fails when the chapter names a featherauth command or
// subcommand the table lacks.
func checkRunbookCommands(t testing.TB, text string, table map[string][]string) {
	t.Helper()
	cmds := guideCommands(text, table)
	if len(cmds) < 5 {
		t.Fatalf("the runbook names only %d featherauth commands", len(cmds))
	}
	if missing := missingCommands(strings.Join(cmds, "\n"), table); len(missing) != 0 {
		t.Fatalf("the runbook names commands the CLI does not have: %v", missing)
	}
}

// Every featherauth command the runbook names exists in the command table of
// the CLI (its usage text, the same text the binary prints), so a runbook that
// names a command that was renamed or never built fails here. The table itself
// is checked first: it must hold the commands the runbook uses.
//
// Covers: FR-20 (part)
// Acceptance: Emergency key rotation (part)
func TestRunbookCommandsExist(t *testing.T) {
	table := commandNames(usage)
	for name, want := range map[string][]string{
		"config": {"init", "check"}, "keys": {"generate", "sealed", "reseal", "clear-sealed"}, "session": {"list", "revoke"},
		"user":        {"get", "list", "update", "disable", "enable", "delete", "link", "unlink"},
		"healthcheck": nil, "serve": nil,
	} {
		subs, ok := table[name]
		if !ok || !slices.Equal(subs, want) {
			t.Fatalf("the command table has %q with %v, want %v", name, subs, want)
		}
	}
	checkRunbookCommands(t, readRunbook(t), table)
}

// The checker itself: a command the table lacks, a subcommand it lacks and an
// empty subcommand are reported; the commands of the table are not.
func TestRunbookCheckerReportsMissingCommands(t *testing.T) {
	table := commandNames(usage)
	for _, tc := range []struct {
		name, text string
		want       []string
	}{
		{"known commands", "featherauth config check <dir>\nfeatherauth session revoke main --all", nil},
		{"import takes a file first", "featherauth import <file> --realm main", nil},
		{"unknown command", "run featherauth key rotate", []string{"featherauth key"}},
		{"unknown subcommand", "featherauth session purge main", []string{"featherauth session purge"}},
		{"command without its subcommand", "featherauth keys", []string{"featherauth keys "}},
		{"unknown user subcommand", "featherauth user explode main 1", []string{"featherauth user explode"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := missingCommands(tc.text, table)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("missing %q, want %q", got, tc.want)
			}
		})
	}
}

// The flags the runbook uses are flags of the real usage text: `--type` takes
// ec and encryption for keys generate, and `--all` is a flag of session revoke.
// Each row is a command line the runbook names and the value or flag it needs.
//
// Covers: FR-20 (part)
// Acceptance: Emergency key rotation (part)
func TestRunbookFlagsExistInUsage(t *testing.T) {
	text := readRunbook(t)
	types := regexp.MustCompile(`--type ([a-z|]+)`).FindStringSubmatch(usage)
	if types == nil {
		t.Fatal("the usage text names no --type values")
	}
	for _, tc := range []struct {
		line, flag, value string
	}{
		{"keys generate --type ec ", "--type", "ec"},
		{"keys generate --type encryption ", "--type", "encryption"},
		{"session revoke <realm> --all", "--all", ""},
	} {
		if !strings.Contains(text, tc.line) {
			t.Errorf("the runbook has no command line %q", tc.line)
		}
		if tc.value != "" {
			if !slices.Contains(strings.Split(types[1], "|"), tc.value) {
				t.Errorf("the usage text does not list %s value %q", tc.flag, tc.value)
			}
		} else if !strings.Contains(usage, tc.flag) {
			t.Errorf("the usage text does not list the flag %s", tc.flag)
		}
	}
}

// The signing-key steps of the runbook, in its order, against the real
// service: a new key replaces the exposed one in one reload, the bearer
// endpoints and the logout refuse the old tokens at once, the refresh and the
// new logins sign with the new key that the JWKS publishes, and the realm's
// sessions end with `session revoke`.
//
// Covers: SEC-07
// Acceptance: Emergency key rotation
func TestEmergencyKeyRotationRunbook(t *testing.T) {
	e := server.New(t)
	env := serviceConfigDir(t, e)
	text := readRunbook(t)
	checkRunbookCommands(t, text, commandNames(usage))
	steps := section(t, text, "### ", "8.1 Exposed signing key")
	at := func(s string) int {
		i := strings.Index(steps, s)
		if i < 0 {
			t.Fatalf("the signing-key steps do not name %q", s)
		}
		return i
	}
	order := []string{"keys generate", "config check", "Reload:", "session revoke <realm> --all"}
	for i := 1; i < len(order); i++ {
		if at(order[i-1]) >= at(order[i]) {
			t.Fatalf("the signing-key steps are not in the order %q, then %q", order[i-1], order[i])
		}
	}

	// Two sessions of one user, at two clients, before the rotation.
	g1 := e.Exchange(t, server.ClientQuery, e.Login(t, server.ClientQuery))
	g2 := e.Exchange(t, server.ClientFragment, e.Login(t, server.ClientFragment))
	uid := userIDOf(t, e, "google", "1001")
	oldKID := tokenHeader(t, g1.AccessToken)["kid"]
	if oldKID != "main-1" {
		t.Fatalf("the access token is signed with %v, want main-1", oldKID)
	}
	if r := e.NewClient().Request(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointUserinfo, ""), "", bearer(g1.AccessToken)); r.Code != http.StatusOK {
		t.Fatalf("before the rotation /userinfo: %d %s", r.Code, r.Body)
	}

	// 1. A new key, with a new kid, from keys generate.
	newKeyFile := filepath.Join(e.ConfigDir(), "secrets", "main", "signing-2.pem")
	if r := exec(t, nil, "keys", "generate", newKeyFile); r.code != 0 {
		t.Fatalf("keys generate: %+v", r)
	}

	// 2. One change to the realm file: the new key active, the exposed key gone.
	oldEntry := "  - { kid: main-1, file: secrets/main/signing.pem, state: active }"
	newEntry := "  - { kid: main-2, file: secrets/main/signing-2.pem, state: active }"
	e.Reload(t, func(y string) string {
		if !strings.Contains(y, oldEntry) {
			t.Fatalf("the realm file has no %q:\n%s", oldEntry, y)
		}
		return strings.Replace(y, oldEntry, newEntry, 1)
	})

	// 3. The configuration checks clean.
	// The fixture's own warning (the legacy public client) is printed, and does
	// not stop the check: the exit code is 0 and no diagnostic is an error.
	if r := exec(t, nil, "config", "check", e.ConfigDir()); r.code != 0 || strings.Contains(r.stdout, ": error:") {
		t.Fatalf("config check after the change: %+v", r)
	}

	// The JWKS publishes the new key only.
	keys := jwksKeys(t, e)
	if len(keys) != 1 || keys[0] != "main-2" {
		t.Fatalf("the JWKS holds %v after the rotation, want only main-2", keys)
	}

	// The tokens signed before are refused at once by FeatherAuth's bearer
	// endpoints and by its logout.
	c := e.NewClient()
	for _, tc := range []struct {
		name, method string
		ep           config.Endpoint
	}{
		{"userinfo", http.MethodGet, config.EndpointUserinfo},
		{"account delete", http.MethodDelete, config.EndpointAccountDelete},
		{"bearer logout", http.MethodPost, config.EndpointLogout},
	} {
		r := c.Request(t, tc.method, e.Realm.EndpointURL(tc.ep, ""), "", bearer(g1.AccessToken))
		if r.Code != http.StatusUnauthorized || !strings.Contains(r.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
			t.Errorf("%s with a token of the removed key: %d %q %s, want 401 invalid_token", tc.name, r.Code, r.Header.Get("WWW-Authenticate"), r.Body)
		}
	}
	// A logout by ID token hint of the removed key ends nothing.
	hint := url.Values{"id_token_hint": {g1.IDToken}, "client_id": {server.ClientQuery.ID}}
	if r := c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointLogout, "")+"?"+hint.Encode(), nil); r.Code != http.StatusBadRequest {
		t.Errorf("logout with a hint of the removed key: %d, want the 400 error page", r.Code)
	}
	if n := len(sessionsOf(t, e, env, uid)); n != 2 {
		t.Fatalf("%d sessions after the refused logout, want the 2 of before", n)
	}

	// A refresh still works and signs with the new key; so does a new login.
	rr := c.PostToken(t, server.RefreshForm(server.ClientQuery, g1.RefreshToken), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh after the rotation: %d %s", rr.Code, rr.Body)
	}
	refreshed := rr.Tokens(t)
	if kid := tokenHeader(t, refreshed.AccessToken)["kid"]; kid != "main-2" {
		t.Errorf("refreshed access token signed with %v, want main-2", kid)
	}
	verifyWithJWKS(t, e, refreshed.AccessToken)
	g3 := e.Exchange(t, server.ClientQuery, e.Login(t, server.ClientQuery))
	verifyWithJWKS(t, e, g3.IDToken)
	verifyWithJWKS(t, e, g3.AccessToken)
	if kid := tokenHeader(t, g3.IDToken)["kid"]; kid != "main-2" {
		t.Errorf("new ID token signed with %v, want main-2", kid)
	}

	// The realm's sessions end with one command: the three sessions of the
	// user (two before the rotation, one after) are listed and then revoked.
	want := []string{sessionOf(t, g1.AccessToken), sessionOf(t, g2.AccessToken), sessionOf(t, g3.AccessToken)}
	slices.Sort(want)
	if got := sortedSessionIDs(t, e, env, uid); !slices.Equal(got, want) {
		t.Fatalf("sessions %v, want %v", got, want)
	}
	// 5. Revoke the sessions of the realm (the runbook's command, with the CLI).
	r := execAt(t, e.Clock, env, "session", "revoke", "main", "--all")
	assertOneAuditLine(t, r, "realm.sessions_revoked")
	if got := sessionsOf(t, e, env, uid); len(got) != 0 {
		t.Fatalf("sessions after session revoke --all: %v", got)
	}
	for _, tk := range []string{refreshed.RefreshToken, g2.RefreshToken, g3.RefreshToken} {
		if rr := c.PostToken(t, server.RefreshForm(server.ClientQuery, tk), nil); rr.Code != http.StatusBadRequest || rr.Tokens(t).Error != "invalid_grant" {
			t.Errorf("refresh after session revoke: %d %s, want invalid_grant", rr.Code, rr.Body)
		}
	}

	// The logs and the CLI's output hold none of the secrets of the run.
	secrets := []string{g1.AccessToken, g1.IDToken, g1.RefreshToken, g2.AccessToken, g2.IDToken, g2.RefreshToken,
		g3.AccessToken, g3.IDToken, g3.RefreshToken, refreshed.AccessToken, refreshed.RefreshToken, server.Verifier}
	for _, p := range logscan.Problems(r.stderr+r.stdout, secrets) {
		t.Errorf("the CLI output: %s", p)
	}
	logscan.WantClean(t, e, secrets...)
}

// bearer is the Authorization header of a bearer request.
func bearer(token string) http.Header {
	return http.Header{"Authorization": {"Bearer " + token}}
}

// tokenHeader decodes the JOSE header of a JWT.
func tokenHeader(t testing.TB, raw string) map[string]any {
	t.Helper()
	return jwtPart(t, raw, 0)
}

// tokenClaims decodes the payload of a JWT.
func tokenClaims(t testing.TB, raw string) map[string]any {
	t.Helper()
	return jwtPart(t, raw, 1)
}

// jwtPart decodes the JSON of one segment of a JWT: 0 is the header, 1 the
// payload.
func jwtPart(t testing.TB, raw string, i int) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", raw)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[i])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// sessionOf returns the sid claim of an access token, the id of its session.
func sessionOf(t testing.TB, access string) string {
	t.Helper()
	s, _ := tokenClaims(t, access)["sid"].(string)
	if s == "" {
		t.Fatal("the access token has no sid")
	}
	return s
}

// jwksKeys returns the kids the realm's JWKS publishes, fetched through the
// service's endpoint.
func jwksKeys(t testing.TB, e *server.Env) []string {
	t.Helper()
	r := e.NewClient().Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointJWKS, ""), nil)
	if r.Code != http.StatusOK {
		t.Fatalf("JWKS: %d %s", r.Code, r.Body)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal([]byte(r.Body), &doc); err != nil {
		t.Fatal(err)
	}
	var kids []string
	for _, k := range doc.Keys {
		kids = append(kids, k.Kid)
	}
	slices.Sort(kids)
	return kids
}

// verifyWithJWKS checks the signature of a token with the keys the JWKS
// publishes, as an API would, and fails the test when it does not verify.
func verifyWithJWKS(t testing.TB, e *server.Env, raw string) {
	t.Helper()
	r := e.NewClient().Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointJWKS, ""), nil)
	set, err := jwk.Parse([]byte(r.Body))
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if _, err := jws.Verify([]byte(raw), jws.WithKeySet(set)); err != nil {
		t.Fatalf("token does not verify with the JWKS: %v", err)
	}
}

// userIDOf returns the user id of a provider identity of the realm.
func userIDOf(t testing.TB, e *server.Env, provider, sub string) string {
	t.Helper()
	ctx := context.Background()
	var uid string
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		ident, err := tx.Identities().Find(ctx, rid, config.ProviderKey(provider), sub)
		uid = string(ident.UserID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return uid
}

// sessionsOf lists the user's active sessions with the CLI.
func sessionsOf(t *testing.T, e *server.Env, env map[string]string, uid string) []map[string]any {
	t.Helper()
	r := execAt(t, e.Clock, env, "session", "list", "main", uid)
	if r.code != 0 {
		t.Fatalf("session list: %+v", r)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &rows); err != nil {
		t.Fatalf("session list is not JSON: %v: %s", err, r.stdout)
	}
	return rows
}

// sortedSessionIDs is the session ids the CLI lists for the user, sorted.
func sortedSessionIDs(t *testing.T, e *server.Env, env map[string]string, uid string) []string {
	t.Helper()
	ids := sessionIDsOf(sessionsOf(t, e, env, uid))
	slices.Sort(ids)
	return ids
}

// The client secret step of the runbook: a new value written to the file of
// the client's client_secret_file and reloaded replaces the old one at once,
// and the old one is refused at the token endpoint.
func TestRunbookClientSecretChangeTakesEffectAtReload(t *testing.T) {
	e := server.New(t)
	app := server.ClientConfidential
	old := e.Secret(app.ID)
	if r := e.NewClient().PostToken(t, server.CodeForm(app, e.Login(t, app), "client_secret", old), nil); r.Code != http.StatusOK {
		t.Fatalf("exchange with the current secret: %d %s", r.Code, r.Body)
	}

	fresh := freshSecret(t)
	file := filepath.Join(e.ConfigDir(), "secrets", "main", "srv_secret")
	if err := os.WriteFile(file, []byte(fresh+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.Reload(t, func(y string) string { return y })
	if got := e.Secret(app.ID); got != fresh {
		t.Fatal("the reload did not read the new client secret")
	}

	// A secret sent in the body is refused with 400 invalid_client (Clients,
	// the confidential client row: 401 is for the basic method only).
	r := e.NewClient().PostToken(t, server.CodeForm(app, e.Login(t, app), "client_secret", old), nil)
	if r.Code != http.StatusBadRequest || r.Tokens(t).Error != "invalid_client" {
		t.Errorf("exchange with the old secret after the reload: %d %s, want 400 invalid_client", r.Code, r.Body)
	}
	if r := e.NewClient().PostToken(t, server.CodeForm(app, e.Login(t, app), "client_secret", fresh), nil); r.Code != http.StatusOK {
		t.Errorf("exchange with the new secret: %d %s", r.Code, r.Body)
	}
}

// freshSecret returns a random client secret of 43 characters.
func freshSecret(t testing.TB) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := io.ReadFull(secure.Default, raw); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// auditRows returns the audit rows of the realm with the action.
func auditRows(t testing.TB, e *server.Env, action string) []store.AuditEvent {
	t.Helper()
	ctx := context.Background()
	var rows []store.AuditEvent
	err := e.Store.Read(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, "main")
		if err != nil {
			return err
		}
		all, err := tx.Audit().List(ctx, rid, e.Clock.Now().Add(-24*time.Hour))
		for _, a := range all {
			if a.Action == action {
				rows = append(rows, a)
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestSecurityFixesWiring runs one login for each provider adapter of the test
// service, with a refresh and the tokens checked against the JWKS. Then it runs
// the security fixes through the same service: the headers of every kind of
// answer, a posted callback that is not a login in progress, a reused refresh
// token, a provider event sent twice, and the rate limit of a /64 in the real
// process. The logs of the whole run are scanned for secrets at the end.
//
// Covers: FR-05 (part), SEC-11 (part), SEC-13 (part), SEC-23 (part), SEC-24 (part), SEC-25 (part), SEC-26 (part), SEC-27 (part), SEC-29 (part)
func TestSecurityFixesWiring(t *testing.T) {
	e := server.New(t)
	var secrets []string
	app := server.ClientQuery
	var apple string

	t.Run("one login and a refresh for every provider", func(t *testing.T) {
		for i, prov := range server.Providers {
			sub := strconv.Itoa(2001 + i) // GitHub ids are numbers
			e.Mocks[prov].SetUser(mockidp.User{
				Sub: sub, Name: "Ann Lee", Email: prov + "@example.com", EmailVerified: true,
				Emails: []mockidp.Email{{Email: prov + "@example.com", Primary: true, Verified: true}},
			})
			if prov == "apple" {
				apple = sub
			}
			res := e.NewClient().Login(t, server.Authorize(app, prov))
			g := e.Exchange(t, app, res)
			verifyWithJWKS(t, e, g.IDToken)
			verifyWithJWKS(t, e, g.AccessToken)
			secrets = append(secrets, res.Values.Get("code"), g.AccessToken, g.IDToken, g.RefreshToken)

			r := e.NewClient().PostToken(t, server.RefreshForm(app, g.RefreshToken), nil)
			if r.Code != http.StatusOK {
				t.Fatalf("%s: refresh %d %s", prov, r.Code, r.Body)
			}
			tk := r.Tokens(t)
			verifyWithJWKS(t, e, tk.AccessToken)
			secrets = append(secrets, tk.AccessToken, tk.RefreshToken)
		}
	})

	t.Run("every kind of answer carries nosniff", func(t *testing.T) {
		c := e.NewClient()
		g := e.Exchange(t, app, e.Login(t, app))
		secrets = append(secrets, g.AccessToken, g.IDToken, g.RefreshToken)
		answers := map[string]server.Response{
			"discovery":   c.Do(t, http.MethodGet, server.Issuer+"/.well-known/openid-configuration", nil),
			"jwks":        c.Do(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointJWKS, ""), nil),
			"userinfo":    c.Request(t, http.MethodGet, e.Realm.EndpointURL(config.EndpointUserinfo, ""), "", bearer(g.AccessToken)),
			"token error": c.PostToken(t, server.RefreshForm(app, "not-a-token"), nil),
			"not found":   c.Do(t, http.MethodGet, server.Issuer+"/no-such-path", nil),
		}
		for name, r := range answers {
			if got := r.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("%s: X-Content-Type-Options %q, want nosniff", name, got)
			}
		}
	})

	t.Run("a posted callback without a login in progress is refused", func(t *testing.T) {
		r := e.NewClient().Do(t, http.MethodPost, e.Realm.EndpointURL(config.EndpointCallback, "apple"),
			url.Values{"state": {"no-such-login"}, "code": {"c"}})
		if r.Code != http.StatusBadRequest {
			t.Errorf("posted callback with an unknown state: %d, want 400", r.Code)
		}
	})

	t.Run("a reused refresh token is recorded", func(t *testing.T) {
		g := e.Exchange(t, app, e.Login(t, app))
		secrets = append(secrets, g.AccessToken, g.IDToken, g.RefreshToken)
		c := e.NewClient()
		if r := c.PostToken(t, server.RefreshForm(app, g.RefreshToken), nil); r.Code != http.StatusOK {
			t.Fatalf("first refresh: %d %s", r.Code, r.Body)
		}
		e.Clock.Advance(31 * time.Second) // past refresh_reuse_grace (30s)
		if r := c.PostToken(t, server.RefreshForm(app, g.RefreshToken), nil); r.Code != http.StatusBadRequest || r.Tokens(t).Error != "invalid_grant" {
			t.Fatalf("reuse after the grace window: %d %s", r.Code, r.Body)
		}
		if n := strings.Count(e.Logs.String(), `"action":"session.reuse_detected"`); n != 1 {
			t.Errorf("%d session.reuse_detected lines, want 1", n)
		}
		if n := len(auditRows(t, e, "session.reuse_detected")); n != 1 {
			t.Errorf("%d session.reuse_detected rows, want 1", n)
		}
	})

	t.Run("a provider event sent twice is acted on once", func(t *testing.T) {
		m := e.Mocks["apple"]
		body := m.SignedEvent(m.ClientID(), "consent-revoked", apple)
		first := e.NewClient().Request(t, http.MethodPost, e.Realm.EndpointURL(config.EndpointProviderEvents, "apple"), body, jsonHeader)
		if first.Code != http.StatusOK {
			t.Fatalf("first event: %d %s", first.Code, first.Body)
		}
		rows := len(auditRows(t, e, "identity.consent_revoked"))
		if rows != 1 {
			t.Fatalf("%d consent_revoked rows after the first event, want 1", rows)
		}
		again := e.NewClient().Request(t, http.MethodPost, e.Realm.EndpointURL(config.EndpointProviderEvents, "apple"), body, jsonHeader)
		if again.Code != first.Code || again.Body != first.Body {
			t.Errorf("the repeat answered %d %q, the first %d %q", again.Code, again.Body, first.Code, first.Body)
		}
		if n := len(auditRows(t, e, "identity.consent_revoked")); n != rows {
			t.Errorf("the repeat wrote %d audit rows", n-rows)
		}
	})

	// The rate limit runs in the real process, behind a trusted proxy that
	// passes the client's address: 31 addresses of one /64 count as one client.
	t.Run("the rate limit counts an IPv6 /64 as one client", func(t *testing.T) {
		serviceConfigDir(t, e)
		editFile(t, filepath.Join(e.ConfigDir(), "server.yaml"), func(y string) string {
			return y + "trusted_proxies: [\"127.0.0.0/8\"]\n"
		})
		p := startProcess(t, e.ConfigDir())
		addr := p.listening(t)
		client := &http.Client{Timeout: processLimit, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		from := func(forwarded string) int {
			t.Helper()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+"/main/token", strings.NewReader(""))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Forwarded-For", forwarded)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			return resp.StatusCode
		}
		for n := 1; n <= 30; n++ {
			if code := from(fmt.Sprintf("2001:db8:0:1::%x", n)); code == http.StatusTooManyRequests {
				t.Fatalf("address %d of the /64 was limited", n)
			}
		}
		if code := from("2001:db8:0:1::ff"); code != http.StatusTooManyRequests {
			t.Errorf("the 31st address of the /64 answered %d, want 429", code)
		}
		if code := from("2001:db8:0:2::1"); code == http.StatusTooManyRequests {
			t.Errorf("an address of another /64 was limited")
		}
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		if code := p.exitCode(t); code != 0 {
			t.Errorf("the service exited %d", code)
		}
	})

	t.Run("the logs of the run hold no secret", func(t *testing.T) {
		secrets = append(secrets, server.Verifier)
		logscan.WantClean(t, e, secrets...)
	})
}

// jsonHeader is the content type of a provider event post.
var jsonHeader = http.Header{"Content-Type": {"application/json"}}
