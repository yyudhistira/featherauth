package oidc

import (
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/web"
)

// ResponseMode says where an authorization result is delivered.
type ResponseMode string

// The response modes the service supports.
const (
	ModeQuery    ResponseMode = "query"
	ModeFragment ResponseMode = "fragment"
	ModeFormPost ResponseMode = "form_post"
)

// ParseResponseMode returns the mode named by a request or client setting.
func ParseResponseMode(s string) (ResponseMode, bool) {
	switch m := ResponseMode(s); m {
	case ModeQuery, ModeFragment, ModeFormPost:
		return m, true
	}
	return "", false
}

// pages renders the pages of the endpoints; it holds only parsed templates.
var pages = web.NewPages()

// Deliver sends an authorization result to the client's redirect URI in the
// given mode: a redirect with the values in the query (kept after the URI's own
// query) or in the fragment, or the form_post page. p carries code or error,
// error_description, state when the request sent one, and iss, which every
// authorization response has (RFC 9207, SEC-19); without iss or with an unknown
// mode nothing is delivered and the answer is a 500.
//
// The realm comes from the request context (server.FromContext). The browser
// security headers of the redirects are set by the router.
func Deliver(w http.ResponseWriter, r *http.Request, mode ResponseMode, redirectURI string, p url.Values) {
	info, _ := server.FromContext(r.Context())
	if p.Get("iss") == "" || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	switch mode {
	case ModeQuery:
		sep := "?"
		base, _, _ := strings.Cut(redirectURI, "#")
		if strings.Contains(base, "?") {
			sep = "&"
			if strings.HasSuffix(base, "?") || strings.HasSuffix(base, "&") {
				sep = ""
			}
		}
		redirect(w, base+sep+p.Encode())
	case ModeFragment:
		base, _, _ := strings.Cut(redirectURI, "#")
		redirect(w, base+"#"+p.Encode())
	case ModeFormPost:
		fields := make([]web.Field, 0, len(p))
		for _, k := range slices.Sorted(maps.Keys(p)) {
			for _, v := range p[k] {
				fields = append(fields, web.Field{Name: k, Value: v})
			}
		}
		pages.Page(w, r, info.Realm, web.Page{Kind: web.PageFormPost, Action: redirectURI, Fields: fields})
	default:
		serverError(w, r, info)
	}
}

func redirect(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// serverError answers a result that cannot be delivered with the error page.
func serverError(w http.ResponseWriter, r *http.Request, info server.Info) {
	if info.Realm == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	pages.Page(w, r, info.Realm, web.Page{Kind: web.PageError, Status: http.StatusInternalServerError, MessageID: "error.server"})
}
