// Package logscan is the secret scan of the service logs (SEC-13) that the
// tests of several packages run over a whole flow.
package logscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// The scan looks for a JWT, an email and a URL with a query or a fragment in
// the logs of a run, captured at log_level debug.

var (
	jwtPattern   = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)
	emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+(@|%40)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	// An absolute URL, or a path, that carries a query or a fragment.
	// The URL may sit inside other text, such as an error message.
	queryURLPattern = regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^\s"]*[?#]|^/[^\s]*[?#]`)
)

// Problems returns what in the logs breaks SEC-13: a secret value, a JWT,
// an email, or a URL with a query or fragment, in any string of any depth.
func Problems(logs string, secrets []string) []string {
	var problems []string
	for _, s := range secrets {
		if s != "" && strings.Contains(logs, s) {
			problems = append(problems, "secret value "+s)
		}
	}
	var walk func(line string, v any)
	walk = func(line string, v any) {
		switch x := v.(type) {
		case string:
			if jwtPattern.MatchString(x) {
				problems = append(problems, "JWT in "+line)
			}
			if emailPattern.MatchString(x) {
				problems = append(problems, "email in "+line)
			}
			if queryURLPattern.MatchString(x) {
				problems = append(problems, "URL with a query or fragment in "+line)
			}
		case map[string]any:
			for k, e := range x {
				walk(line, k) // keys too
				walk(line, e)
			}
		case []any:
			for _, e := range x {
				walk(line, e)
			}
		}
	}
	for _, line := range strings.Split(logs, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			problems = append(problems, "line is not JSON: "+line)
			continue
		}
		walk(line, v)
	}
	// The raw text too, for a JWT or an email outside a JSON string value.
	if jwtPattern.MatchString(logs) {
		problems = append(problems, "JWT in the raw logs")
	}
	if emailPattern.MatchString(logs) {
		problems = append(problems, "email in the raw logs")
	}
	return problems
}

// FileSecrets are the contents of every secret file of the configuration
// directory: provider secrets, client secrets, signing keys, encryption key.
func FileSecrets(t testing.TB, e *server.Env) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(filepath.Join(e.ConfigDir(), "secrets"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(b), "\n") {
			// PEM armour lines are public text; the body lines are the secret.
			if line = strings.TrimSpace(line); len(line) >= 16 && !strings.HasPrefix(line, "-----") {
				out = append(out, line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Six text secrets, the signing key, the Apple key and the encryption key
	// give at least one line each; the floor of 16 characters is below the
	// 43 of configdir.Secret and the 44 of the encryption key.
	if len(out) < 10 {
		t.Fatalf("only %d secret lines read from the configuration directory", len(out))
	}
	return out
}

// MockSecrets are the secrets that reached the mock identity providers: the
// provider codes, code verifiers, client secrets, refresh and access tokens.
func MockSecrets(e *server.Env) []string {
	var out []string
	for _, m := range e.Mocks {
		out = append(out, m.ClientSecret(), m.RefreshToken())
		for _, r := range m.Requests() {
			for _, k := range []string{"code", "code_verifier", "client_secret", "refresh_token", "access_token", "state"} {
				out = append(out, r.Form.Get(k), r.Query.Get(k))
			}
			for _, k := range []string{"Authorization", "Cookie"} {
				v := r.Header.Get(k)
				out = append(out, v, strings.TrimPrefix(v, "Bearer "))
			}
		}
	}
	return out
}

// Derived adds what a JWT secret turns into on its way: its header, payload
// and signature segments (each at least 16 characters). Base64 forms of a
// secret are added by the caller, which knows the client id.
func Derived(secrets []string) []string {
	var out []string
	for _, s := range secrets {
		if parts := strings.Split(s, "."); len(parts) == 3 && strings.HasPrefix(s, "eyJ") {
			for _, p := range parts {
				if len(p) >= 16 {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

// WantClean fails the test when the logs of e hold any of the secrets or
// anything else the scan rejects. The logs must not be empty. The harness
// logs at debug level (server.New), the most talkative one.
func WantClean(t testing.TB, e *server.Env, secrets ...string) {
	t.Helper()
	logs := e.Logs.String()
	if !strings.Contains(logs, `"msg":"request"`) {
		t.Fatalf("the flow left no request line, the scan would prove little:\n%s", logs)
	}
	files, mocks := FileSecrets(t, e), MockSecrets(e)
	secrets = slices.DeleteFunc(slices.Clone(secrets), func(s string) bool { return s == "" }) // a public client has no secret
	all := slices.DeleteFunc(append(append(slices.Clone(secrets), files...), mocks...), func(s string) bool { return s == "" })
	// The lists must really hold values: the fixtures of the flow and what the
	// mock providers received.
	if len(secrets) < 10 {
		t.Fatalf("only %d secrets from the flow to scan", len(secrets))
	}
	if n := len(slices.DeleteFunc(slices.Clone(mocks), func(s string) bool { return s == "" })); n < 3 {
		t.Fatalf("the mock providers received only %d secret values", n)
	}
	all = append(all, Derived(all)...)
	for _, p := range Problems(logs, all) {
		t.Error(p)
	}
}
