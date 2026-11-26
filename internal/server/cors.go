package server

import (
	"net/http"
	"slices"
	"strings"

	"github.com/yyudhistira/featherauth/internal/config"
)

// corsMethods are the methods a preflight announces, by endpoint. Only the
// endpoints a browser calls have an entry (web_origins): the others get no CORS
// handling.
var corsMethods = map[string]string{
	"token":     "POST, OPTIONS",
	"revoke":    "POST, OPTIONS",
	"sessions":  "GET, OPTIONS",
	"userinfo":  "GET, POST, OPTIONS",
	"jwks":      "GET, OPTIONS",
	"discovery": "GET, OPTIONS",
}

// corsHeaders are the request headers a browser may send: Authorization for
// the bearer and Basic credentials, Content-Type for the token form.
const corsHeaders = "Authorization, Content-Type"

// corsHeadersDPoP adds the DPoP header, which the endpoints that take a proof
// accept (FR-44).
const corsHeadersDPoP = corsHeaders + ", DPoP"

// corsDPoP are the endpoints that accept the DPoP header.
var corsDPoP = map[string]bool{"token": true, "userinfo": true, "sessions": true}

// CORS is the middleware of the API endpoints a browser calls (token,
// userinfo, JWKS and discovery); it needs the Router's routing information,
// so it is applied inside the router and passes on any request that has none.
//
//   - A preflight (OPTIONS with Access-Control-Request-Method) is answered here
//     with 204: for an origin registered in web_origins by any client of the
//     realm it carries the allowed origin, the endpoint's methods and headers;
//     for any other origin it carries no CORS headers.
//   - The actual request to discovery or the JWKS gets the allowed origin when
//     any client of the realm registers it.
//   - The actual request to the token endpoint or userinfo is checked against
//     the client the handler authenticated (the token's client, or the access
//     token's azp client): the handler calls AllowOrigin.
//
// Responses carry Vary: Origin. The allowed origin is always the request's own
// origin, never a wildcard.
func CORS() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			info, ok := FromContext(r.Context())
			methods, handled := corsMethods[info.Endpoint]
			if !ok || info.Realm == nil || !handled {
				next.ServeHTTP(w, r)
				return
			}
			addVary(w.Header())
			origin := r.Header.Get("Origin")
			preflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
			switch {
			case preflight:
				if origin != "" && registeredByAny(info.Realm, origin) {
					h := w.Header()
					h.Set("Access-Control-Allow-Origin", origin)
					h.Set("Access-Control-Allow-Methods", methods)
					headers := corsHeaders
					if corsDPoP[info.Endpoint] {
						headers = corsHeadersDPoP
					}
					h.Set("Access-Control-Allow-Headers", headers)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			case origin != "" && (info.Endpoint == "discovery" || info.Endpoint == "jwks") && registeredByAny(info.Realm, origin):
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AllowOrigin checks the Origin of a request against the web_origins of the
// client it was made for, for the handlers that know the client (the token
// endpoint and userinfo). A request without an Origin header is not a
// cross-origin browser request and is allowed. An allowed origin is put in
// Access-Control-Allow-Origin; for any other, none is, and the result is false,
// so the browser does not give the response to the page and the handler can
// refuse. A nil client allows no origin.
func AllowOrigin(w http.ResponseWriter, r *http.Request, c *config.Client) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	addVary(w.Header())
	if c == nil || !slices.Contains(c.WebOrigins, origin) {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	return true
}

// registeredByAny reports whether any client of the realm lists origin.
func registeredByAny(realm *config.Realm, origin string) bool {
	for _, c := range realm.Clients {
		if slices.Contains(c.WebOrigins, origin) {
			return true
		}
	}
	return false
}

// addVary adds Origin to Vary once.
func addVary(h http.Header) {
	for _, v := range h.Values("Vary") {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), "Origin") {
				return
			}
		}
	}
	h.Add("Vary", "Origin")
}
