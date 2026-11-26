package web

import (
	"net/http"

	"github.com/yyudhistira/featherauth/internal/config"
)

// SecurityHeaders sets the headers every browser page carries (SEC-12): HSTS
// and the Content-Security-Policy as the realm sets them (an empty value omits
// the header), and the fixed ones.
func SecurityHeaders(realm *config.Realm, h http.Header) {
	if v := realm.SecurityHeaders.HSTS; v != "" {
		h.Set("Strict-Transport-Security", v)
	}
	if v := realm.SecurityHeaders.ContentSecurityPolicy; v != "" {
		h.Set("Content-Security-Policy", v)
	}
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}
