//go:build browser

package server_test

import (
	"strings"
	"testing"

	"github.com/chromedp/chromedp"

	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// Covers: FR-45 (part), SEC-37 (part)
// Acceptance: Single sign-on session (part)
// Two client applications in one Chrome profile: after the login at the first, the
// second client's login shows no chooser and does not contact the provider, and it
// ends at the second client's callback. The browser session cookie is set by the
// first login, with the realm's name in it.
func TestBrowserSecondLoginShowsNoChooser(t *testing.T) {
	s, ctx := start(t, nil)
	s.env.Reload(t, func(y string) string {
		return strings.Replace(y, "name: main\n", "name: main\nsso:\n  enabled: true\n", 1)
	})
	tab, cancel := chromedp.NewContext(ctx)
	defer cancel()

	var first string
	if err := chromedp.Run(tab,
		chromedp.Navigate(authorizeURL(s.env, server.Authorize(server.ClientQuery, "google"))),
		chromedp.Location(&first),
	); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "https://app.example.com/callback") {
		t.Fatalf("the first login ended at %s", first)
	}
	cookieSet := false
	for _, r := range s.find(func(r seen) bool { return r.Host == "auth.example.com" }) {
		for _, c := range r.SetCookies {
			cookieSet = cookieSet || c.Name == "fa_sso_main"
		}
	}
	if !cookieSet {
		t.Fatal("the first login set no browser session cookie")
	}

	before := len(s.env.Mocks["google"].Authorizations())
	var second string
	if err := chromedp.Run(tab,
		chromedp.Navigate(authorizeURL(s.env, server.Authorize(server.ClientFormPost, ""))),
		chromedp.Location(&second),
	); err != nil {
		t.Fatal(err)
	}
	if got := len(s.env.Mocks["google"].Authorizations()); got != before {
		t.Fatalf("the second login contacted the provider %d times", got-before)
	}
	if !strings.HasPrefix(second, "https://post.example.com/callback") {
		t.Fatalf("the second login ended at %s, not at the second client (a chooser?)", second)
	}
}
