//go:build browser

package server_test

import (
	"strings"
	"testing"

	"github.com/chromedp/chromedp"

	"github.com/yyudhistira/featherauth/internal/testutil/server"
)

// Covers: FR-50 (part)
// Acceptance: Built-in languages (part)
// The chooser in Indonesian fits a 360 by 640 screen: Chrome asks for id, the page
// is marked id, and no button leaves the width of the screen or the page scrolls
// sideways.
func TestBrowserIndonesianChooserFitsA360By640Screen(t *testing.T) {
	// Chrome asks for Indonesian on every request (its Accept-Language header).
	s, ctx := start(t, []string{"--accept-lang=id", "--lang=id"})
	s.env.Reload(t, func(y string) string {
		return strings.Replace(y, "login_page:\n  contact: help@example.com\n", "login_page:\n  contact: help@example.com\n  supported_locales: [en, id]\n", 1)
	})
	tab, cancel := chromedp.NewContext(ctx)
	defer cancel()
	var lang string
	var noOverflow, buttonsInside bool
	err := chromedp.Run(tab,
		chromedp.EmulateViewport(360, 640),
		chromedp.Navigate(authorizeURL(s.env, server.Authorize(server.ClientQuery, ""))),
		chromedp.WaitVisible(".providers a.button", chromedp.ByQuery),
		chromedp.Evaluate(`document.documentElement.lang`, &lang),
		chromedp.Evaluate(`document.documentElement.scrollWidth <= window.innerWidth`, &noOverflow),
		chromedp.Evaluate(`Array.from(document.querySelectorAll('.providers a.button')).every(b => {
			const r = b.getBoundingClientRect();
			return r.left >= 0 && r.right <= window.innerWidth;
		})`, &buttonsInside),
	)
	if err != nil {
		t.Fatal(err)
	}
	if lang != "id" {
		t.Errorf("the page language is %q, want id", lang)
	}
	if !noOverflow {
		t.Error("the page scrolls sideways at 360 pixels")
	}
	if !buttonsInside {
		t.Error("a provider button leaves the 360-pixel screen")
	}
}
