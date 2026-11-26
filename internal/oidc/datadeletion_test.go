package oidc_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// Covers: FR-34, FR-32 (part), SEC-12 (part)
// Acceptance: Data-deletion page
func TestDataDeletionPageShowsInstructionsAndContact(t *testing.T) {
	e := server.New(t)
	r := e.NewClient().Request(t, http.MethodGet, server.Issuer+"/data-deletion", "", nil)
	if r.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", r.Code)
	}
	if !strings.Contains(r.Body, "delete-account option in the app") {
		t.Errorf("no instructions: %s", r.Body)
	}
	if !strings.Contains(r.Body, "mailto:help@example.com") {
		t.Errorf("no contact: %s", r.Body)
	}
	for k, v := range map[string]string{"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex"} {
		if r.Header.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, r.Header.Get(k), v)
		}
	}
	if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP = %q", csp)
	}
	if r.Header.Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS")
	}

	// Facebook is enabled in the test realm: without a contact the check fails.
	diags := e.ReloadDiagnostics(t, func(y string) string {
		return strings.Replace(y, "login_page:\n  contact: help@example.com\n", "", 1)
	})
	found := false
	for _, d := range diags {
		if d.Field == "login_page.contact" {
			found = true
		}
	}
	if !found {
		t.Errorf("no login_page.contact error: %v", diags)
	}
}

// Covers: FR-34 (part), FR-21 (part), FR-58 (part)
// Acceptance: Wrong method (part)
func TestDataDeletionWrongMethod(t *testing.T) {
	e := server.New(t)
	r := e.NewClient().Request(t, http.MethodPost, server.Issuer+"/data-deletion", "", nil)
	if r.Code != http.StatusMethodNotAllowed || r.Header.Get("Allow") == "" {
		t.Errorf("%d %v", r.Code, r.Header)
	}
}

// Covers: FR-40, SEC-33
// Acceptance: Meta deletion callback
func TestDataDeletionPageShowsAConfirmationCode(t *testing.T) {
	const code = "aB3dE5gH7jK9mN1pQ3rS5t"
	const sentence = "Deletion requests are carried out at once. Your confirmation code is"
	e := server.New(t)
	get := func(query string) server.Response {
		t.Helper()
		return e.NewClient().Request(t, http.MethodGet, server.Issuer+"/data-deletion"+query, "", nil)
	}
	r := get("?code=" + code)
	if r.Code != http.StatusOK || !strings.Contains(r.Body, sentence) || !strings.Contains(r.Body, "<code>"+code+"</code>") {
		t.Fatalf("status %d, no sentence and code in %s", r.Code, r.Body)
	}
	for _, want := range []string{"delete-account option in the app", "mailto:help@example.com"} {
		if !strings.Contains(r.Body, want) { // the page stays the instructions page
			t.Errorf("the page lost %q", want)
		}
	}
	if r.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", r.Header.Get("Cache-Control"))
	}
	for name, query := range map[string]string{
		"a script":                 "?code=" + "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
		"21 characters":            "?code=" + code[:21],
		"23 characters":            "?code=" + code + "x",
		"no code":                  "",
		"an empty code":            "?code=",
		"two codes":                "?code=" + code + "&code=" + code,
		"a dash":                   "?code=" + code[:21] + "-",
		"an underscore":            "?code=" + code[:21] + "_",
		"a space":                  "?code=" + code[:21] + "%20",
		"a letter with an accent":  "?code=" + code[:21] + "%C3%A9",
		"22 digits and a newline":  "?code=" + code[:21] + "%0A",
		"the code as a path":       "/" + code,
		"the code in another name": "?confirmation_code=" + code,
	} {
		r := get(query)
		if strings.Contains(r.Body, sentence) || strings.Contains(r.Body, "<code>") || strings.Contains(r.Body, "<script>alert") {
			t.Errorf("%s: the page shows the sentence or the value: %s", name, r.Body)
		}
		if name != "the code as a path" && r.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", name, r.Code)
		}
	}
}
