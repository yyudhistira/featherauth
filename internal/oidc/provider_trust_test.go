package oidc_test

import (
	"strings"
	"testing"

	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// trust_email at its non-default values, over a full login: a provider that is
// trusted by default (Google) and set to false gives an unverified email that
// links to nobody, and one that is untrusted by default (a generic OpenID
// Connect provider) and set to true gives a verified one that auto-links. The
// same provider at its default does the opposite.
//
// Covers: FR-56 (part)
// Acceptance: Provider options (part)
func TestTrustEmailOptionEndToEnd(t *testing.T) {
	forEachFlowDriver(t, func(t *testing.T, o []server.Option) {
		app := server.ClientQuery
		verified := func(t *testing.T, e *server.Env, key, sub, email string) (string, any) {
			t.Helper()
			flowUser(e, key, sub, email, true)
			tk := flowSignIn(t, e, app, key)
			return subOf(t, tk), flowUserinfo(t, e, tk.AccessToken)["email_verified"]
		}
		t.Run("google false", func(t *testing.T) {
			e := flowNew(t, o)
			e.Reload(t, func(y string) string {
				return strings.Replace(y, "  google:\n    enabled: true\n", "  google:\n    enabled: true\n    trust_email: false\n", 1)
			})
			_, got := verified(t, e, "google", "201", flowGmail("ann"))
			if got == true {
				t.Fatalf("email_verified %v with trust_email false", got)
			}
			// A trusted provider's verified email does not link to the untrusted one.
			a, _ := verified(t, e, "apple", "301", flowGmail("ann"))
			g := subOf(t, flowSignIn(t, e, app, "google"))
			if a == g || flowCount(flowAudit(t, e), "identity.auto_link") != 0 {
				t.Fatalf("an untrusted email linked: %s %s", a, g)
			}
		})
		t.Run("google default", func(t *testing.T) {
			e := flowNew(t, o)
			if _, got := verified(t, e, "google", "201", flowGmail("ann")); got != true {
				t.Fatalf("email_verified %v with the default trust_email", got)
			}
		})
		t.Run("generic true", func(t *testing.T) {
			e := flowNew(t, o)
			e.Reload(t, func(y string) string {
				return strings.Replace(y, "    display_name: Corp\n", "    display_name: Corp\n    trust_email: true\n", 1)
			})
			g, _ := verified(t, e, "google", "201", flowGmail("ann"))
			c, got := verified(t, e, "corp", "7001", flowGmail("ann"))
			if got != true || c != g || flowCount(flowAudit(t, e), "identity.auto_link") != 1 {
				t.Fatalf("email_verified %v, users %s and %s, want a verified auto-link", got, g, c)
			}
		})
		t.Run("generic default", func(t *testing.T) {
			e := flowNew(t, o)
			if _, got := verified(t, e, "corp", "7001", flowGmail("ann")); got == true {
				t.Fatalf("email_verified %v with the default trust_email", got)
			}
		})
	})
}
