package server

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/web"
)

// route is one endpoint of the configured paths.
type route struct {
	name    string
	kind    Kind
	re      *regexp.Regexp
	holders []string // "realm" or "provider", in the order of the capture groups
	handler http.Handler
}

type table struct {
	snap   *config.Snapshot
	routes []route
}

type matched struct {
	route    *route
	realm    config.RealmName
	provider config.ProviderKey
}

const discoverySuffix = "/.well-known/openid-configuration"

var placeholder = regexp.MustCompile(`\{(realm|provider)\}`)

// compile turns a path template into an anchored pattern. {prefix} is
// replaced by the configured prefix; {realm} and {provider} match one path
// segment. suffix is a literal added after the template, and prefixMatch makes
// the pattern accept anything below the template path.
func compile(tmpl, prefix, suffix string, below bool) (*regexp.Regexp, []string) {
	tmpl = strings.ReplaceAll(tmpl, "{prefix}", prefix)
	var (
		b       strings.Builder
		holders []string
		pos     int
	)
	b.WriteString("^")
	for _, loc := range placeholder.FindAllStringSubmatchIndex(tmpl, -1) {
		b.WriteString(regexp.QuoteMeta(tmpl[pos:loc[0]]))
		b.WriteString("([^/]+)")
		holders = append(holders, tmpl[loc[2]:loc[3]])
		pos = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(tmpl[pos:] + suffix))
	if below {
		b.WriteString("/.+")
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String()), holders
}

// buildTable builds the routes of every endpoint from the snapshot's path
// templates.
func buildTable(snap *config.Snapshot, h Handlers, mw Middleware) *table {
	srv := snap.Server()
	u, ep := srv.URLs, srv.URLs.Endpoints
	t := &table{snap: snap}
	add := func(name string, k Kind, tmpl, suffix string, below bool, fn http.HandlerFunc) {
		re, holders := compile(tmpl, u.PathPrefix, suffix, below)
		t.routes = append(t.routes, route{name: name, kind: k, re: re, holders: holders, handler: chain(name, k, fn, mw)})
	}
	add("discovery", KindAPI, u.Issuer, discoverySuffix, false, h.Discovery)
	add("authorize", KindBrowser, ep.Authorize, "", false, h.Authorize)
	add("callback", KindBrowser, ep.Callback, "", false, h.Callback)
	add("continue", KindBrowser, ep.Callback, "/continue", false, h.CallbackContinue)
	add("token", KindAPI, ep.Token, "", false, h.Token)
	add("userinfo", KindAPI, ep.Userinfo, "", false, h.Userinfo)
	add("jwks", KindAPI, ep.JWKS, "", false, h.JWKS)
	add("logout", KindBrowser, ep.Logout, "", false, h.Logout)
	add("revoke", KindAPI, ep.Revoke, "", false, h.Revoke)
	add("sessions", KindAPI, ep.Sessions, "", false, h.Sessions)
	add("account_delete", KindAPI, ep.AccountDelete, "", false, h.AccountDelete)
	add("assets", KindBrowser, ep.Assets, "", true, h.Assets)
	add("provider_events", KindAPI, ep.ProviderEvents, "", false, h.ProviderEvents)
	add("data_deletion", KindBrowser, ep.DataDeletion, "", false, h.DataDeletion)
	return t
}

// rateLimited are the endpoints under the per-address rate limit (SEC-11).
var rateLimited = map[string]bool{
	"authorize": true, "callback": true, "continue": true, "token": true, "provider_events": true, "revoke": true,
}

// chain wraps an endpoint's handler. From the outside in: the browser security
// headers (browser endpoints), CORS (API endpoints), the rate limit (the
// endpoints of SEC-11), the body limit. CORS sits outside the rate limit, so
// preflights do not use up the budget, and the headers are set before the
// handler runs, so a handler that needs its own (the form_post page's policy)
// replaces them.
func chain(name string, k Kind, fn http.HandlerFunc, mw Middleware) http.Handler {
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limitBody(w, r, k) {
			fn(w, r)
		}
	})
	if rateLimited[name] && mw.Limit != nil {
		h = mw.Limit(h)
	}
	switch k {
	case KindAPI:
		if mw.CORS != nil {
			h = mw.CORS(h)
		}
	case KindBrowser:
		inner := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if info, ok := FromContext(r.Context()); ok && info.Realm != nil {
				web.SecurityHeaders(info.Realm, w.Header())
			}
			inner.ServeHTTP(w, r)
		})
	}
	return h
}

// match finds the route of a request path. A template that names {realm}
// twice matches only when both are the same.
func (t *table) match(path string) (matched, bool) {
	for i := range t.routes {
		r := &t.routes[i]
		sub := r.re.FindStringSubmatch(path)
		if sub == nil {
			continue
		}
		m := matched{route: r}
		consistent := true
		for j, name := range r.holders {
			v := sub[j+1]
			switch name {
			case "realm":
				if m.realm != "" && string(m.realm) != v {
					consistent = false
				}
				m.realm = config.RealmName(v)
			case "provider":
				if m.provider != "" && string(m.provider) != v {
					consistent = false
				}
				m.provider = config.ProviderKey(v)
			}
		}
		if consistent {
			return m, true
		}
	}
	return matched{}, false
}
