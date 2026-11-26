package oidc_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/logscan"
	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// Scanning the service logs for secrets (SEC-13): the logs of a run, captured
// at log_level debug, hold none of the fixture secret values, no JWT, no
// email, and no URL with a query or fragment. The scan itself is shared with
// the other packages' flows (internal/testutil/logscan); these names delegate
// to it so the tests here read as before.

func logProblems(logs string, secrets []string) []string { return logscan.Problems(logs, secrets) }

func derived(secrets []string) []string { return logscan.Derived(secrets) }

func fileSecrets(t *testing.T, e *server.Env) []string { return logscan.FileSecrets(t, e) }

func wantCleanLogs(t *testing.T, e *server.Env, secrets ...string) {
	t.Helper()
	logscan.WantClean(t, e, secrets...)
}

// wantUserIDsInLogs checks that the logs identify people by user id and the
// client by IP: every request line has a path and a client IP, there are audit
// lines, and the audit lines that concern a user carry its user id.
func wantUserIDsInLogs(t *testing.T, logs string, wantAudit bool) {
	t.Helper()
	var requests, audits, withUser int
	for _, line := range strings.Split(logs, "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line is not JSON: %s", line)
		}
		switch {
		case m["msg"] == "request":
			requests++
			if m["client_ip"] == nil || m["path"] == nil {
				t.Errorf("request line without path or client_ip: %s", line)
			}
		case m["audit"] == true:
			audits++
			if id, _ := m["user_id"].(string); id != "" {
				withUser++
			}
			if _, ok := m["email"]; ok {
				t.Errorf("audit line with an email: %s", line)
			}
		}
	}
	if requests == 0 || (wantAudit && (audits == 0 || withUser == 0)) {
		t.Errorf("%d request lines, %d audit lines, %d audit lines with a user id", requests, audits, withUser)
	}
}

// The scan itself must find what it looks for: a planted secret, JWT, email
// and URLs with a query or a fragment are all reported, a clean log is not.
//
// Covers: SEC-13 (part)
func TestLogScanFindsWhatItLooksFor(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"
	segments := derived([]string{"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0abcdefghijk.c2lnbmF0dXJlLXNlZ21lbnQ"})
	if len(segments) != 3 {
		t.Fatalf("derived segments: %v", segments)
	}
	clean := `{"level":"DEBUG","msg":"request","path":"/main/token","status":200,"user":"u-1","code":"[redacted]"}` + "\n"
	if got := logProblems(clean, []string{"s3cret-value"}); len(got) != 0 {
		t.Fatalf("clean logs reported: %v", got)
	}
	for name, line := range map[string]string{
		"secret":       `{"msg":"x","detail":"has s3cret-value inside"}`,
		"jwt":          `{"msg":"x","detail":"` + jwt + `"}`,
		"nested jwt":   `{"msg":"x","g":{"l":["` + jwt + `"]}}`,
		"email":        `{"msg":"x","detail":"ann@example.com"}`,
		"escaped mail": `{"msg":"x","detail":"ann%40example.com"}`,
		"url query":    `{"msg":"x","url":"https://idp.example/auth?code=1"}`,
		"url fragment": `{"msg":"x","url":"https://idp.example/cb#id_token=1"}`,
		"path query":   `{"msg":"x","path":"/main/authorize?state=1"}`,
		"not json":     `plain text`,
		"embedded url": `{"msg":"x","error":"Get \"https://idp.example/token?code=1\": dial tcp"}`,
		"embedded frg": `{"msg":"x","error":"redirect to http://a.example/cb#access_token=1 failed"}`,
		"in a key":     `{"msg":"x","g":{"https://a.example/x?y=1":"v"}}`,
		"email in key": `{"msg":"x","g":{"ann@example.com":"v"}}`,
		"jwt segment":  `{"msg":"x","detail":"payload ` + segments[1] + `"}`,
	} {
		if got := logProblems(line+"\n", append([]string{"s3cret-value"}, segments...)); len(got) == 0 {
			t.Errorf("%s: nothing reported", name)
		}
	}
}

// The scan can fail on the live output of the service: the real logs of a
// login are clean, and the same logs with one unredacted line holding the
// login's state and nonce are not.
//
// Covers: SEC-13 (part)
func TestLogScanFailsOnLiveOutput(t *testing.T) {
	e := server.New(t)
	const state, nonce = "state-fixture-0a1b2c", "nonce-fixture-3d4e5f"
	res := e.NewClient().Login(t, server.Authorize(server.Clients[0], "google", "state", state, "nonce", nonce))
	secrets := append([]string{state, nonce, res.Values.Get("code")}, fileSecrets(t, e)...)
	logs := e.Logs.String()
	if logs == "" {
		t.Fatal("no logs")
	}
	if got := logProblems(logs, secrets); len(got) != 0 {
		t.Fatalf("the live logs are not clean: %v", got)
	}
	leaked := logs + `{"level":"INFO","msg":"callback","detail":"state=` + state + ` nonce=` + nonce + `"}` + "\n"
	if got := logProblems(leaked, secrets); len(got) != 2 {
		t.Fatalf("the scan found %v in the leaking logs, want the state and the nonce", got)
	}
}

// An auto-link writes an audit entry: its log line names the user by id, no
// line holds the address, and the scan of the whole run stays clean.
//
// Covers: SEC-13 (part)
func TestAuditLinesHoldUserIDsNotEmails(t *testing.T) {
	e := server.New(t)
	app := server.Clients[0]
	flowUser(e, "google", "201", "Foo@gmail.com", true)
	first := flowSignIn(t, e, app, "google")
	flowUser(e, "apple", "301", " foo@gmail.com ", "true")
	second := flowSignIn(t, e, app, "apple")
	if flowCount(flowAudit(t, e), "identity.auto_link") != 1 {
		t.Fatal("no auto-link audit row")
	}
	wantUserIDsInLogs(t, e.Logs.String(), true)
	secrets := []string{"Foo@gmail.com", "foo@gmail.com"}
	for _, tk := range []server.Tokens{first, second} {
		secrets = append(secrets, tk.AccessToken, tk.RefreshToken, tk.IDToken)
	}
	secrets = append(secrets, "gmail.com", "st-1", "n-1-padding")
	wantCleanLogs(t, e, secrets...)
}
