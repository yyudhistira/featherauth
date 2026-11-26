package oidc

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/token"
	"github.com/yyudhistira/featherauth/internal/web"
)

// AuthorizeConfig is what the authorization endpoint needs.
type AuthorizeConfig struct {
	// Registry gives the provider adapters; required.
	Registry provider.Registry
	// Store keeps the logins in progress; required.
	Store store.Store
	// Clock is the source of time; required.
	Clock clock.Clock
	// Random is the source of state, nonces and verifiers; nil means
	// secure.Default.
	Random secure.Source
	// Log is the service logger (logx); required.
	Log *slog.Logger
	// Verifier checks the id_token_hint of a prompt=none request (FR-45); required.
	Verifier *token.Verifier
	// Codes issues the code of a request answered from a browser session; required.
	Codes *token.Codes
}

// Authorize is the authorization endpoint: it checks the request, answers it
// from a browser session when the session may be used (FR-45), and otherwise
// picks the provider and starts the login there.
type Authorize struct {
	reg   provider.Registry
	store store.Store
	clock clock.Clock
	rand  secure.Source
	log   *slog.Logger
	hints hintVerifier
	codes *token.Codes
}

var _ http.Handler = (*Authorize)(nil)

// NewAuthorize returns the authorization endpoint.
func NewAuthorize(c AuthorizeConfig) *Authorize {
	a := &Authorize{reg: c.Registry, store: c.Store, clock: c.Clock, rand: c.Random, log: c.Log, codes: c.Codes}
	if c.Verifier != nil {
		a.hints = c.Verifier
	}
	if a.rand == nil {
		a.rand = secure.Default
	}
	return a
}

// ServeHTTP answers a GET or a form POST of /{realm}/authorize: the error page
// or an error redirect for a bad request, the provider chooser, or the
// redirect to the provider with the state cookie set. The realm comes from the
// request context (server.FromContext).
func (a *Authorize) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	if !server.AllowMethods(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	ctx, realm := r.Context(), info.Realm
	if !realm.Enabled {
		a.log.InfoContext(ctx, "authorization refused: the realm is disabled", "realm", string(realm.Name))
		pages.Page(w, r, realm, web.Page{Kind: web.PageError, Status: http.StatusForbidden, MessageID: "error.realm_disabled"})
		return
	}

	v, err := authorizeValues(r)
	if err != nil {
		a.log.InfoContext(ctx, "authorization request rejected", "realm", string(realm.Name), "reason", "the form cannot be read")
		pages.Page(w, r, realm, web.Page{Kind: web.PageError, Status: http.StatusBadRequest, MessageID: "error.invalid_request"})
		return
	}
	req, page, redirectErr := checkAuthorization(realm, v, true)
	switch {
	case page != nil:
		a.log.InfoContext(ctx, "authorization request rejected", "realm", string(realm.Name), "reason", page.Reason)
		pages.Page(w, r, realm, web.Page{Kind: web.PageError, Status: page.Status, MessageID: page.MessageID})
		return
	case redirectErr != nil:
		a.deliverError(w, r, redirectErr)
		return
	}
	if a.silentLogin(w, r, req, v) {
		return
	}

	sel := chooseProvider(ctx, a.reg, a.log, req, v)
	switch {
	case sel.err != nil:
		a.deliverError(w, r, sel.err)
		return
	case sel.adapter == nil:
		pages.Page(w, r, realm, web.Page{Kind: web.PageChooser, Providers: sel.buttons})
		return
	}

	started, err := a.startLogin(ctx, req, sel.key, sel.adapter)
	if err != nil {
		a.log.ErrorContext(ctx, "starting the login failed", "realm", string(realm.Name), "provider", string(sel.key), "err", err)
		a.deliverError(w, r, &RedirectError{
			Err:  Error{Code: "server_error", Description: "the login could not be started"},
			Mode: req.ResponseMode, RedirectURI: req.RedirectURI, State: req.State,
		})
		return
	}
	http.SetCookie(w, started.cookie)
	redirect(w, started.location)
}

// authorizeValues returns the parameters of the request: the query of a GET,
// the form of a POST (OIDC Core 3.1.2.1). A POST reads its body only.
func authorizeValues(r *http.Request) (url.Values, error) {
	if r.Method == http.MethodGet {
		return r.URL.Query(), nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return r.PostForm, nil
}

// deliverError answers a request error to the client in the request's
// response mode, with iss and the state when the client sent one.
func (a *Authorize) deliverError(w http.ResponseWriter, r *http.Request, e *RedirectError) {
	info, _ := server.FromContext(r.Context())
	a.log.InfoContext(r.Context(), "authorization request refused",
		"realm", string(info.Realm.Name), "error", e.Err.Code, "reason", e.Err.Description)
	Deliver(w, r, e.Mode, e.RedirectURI, e.Values(info.Realm.Issuer()))
}
