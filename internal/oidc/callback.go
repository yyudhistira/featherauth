package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/token"
	"github.com/yyudhistira/featherauth/internal/user"
	"github.com/yyudhistira/featherauth/internal/web"
)

// CallbackConfig is what the callback endpoint needs.
type CallbackConfig struct {
	// Registry gives the provider adapters; required.
	Registry provider.Registry
	// Store keeps the logins in progress; required.
	Store store.Store
	// Clock is the source of time; required.
	Clock clock.Clock
	// Random is the source of random ids; nil means secure.Default.
	Random secure.Source
	// Log is the service logger (logx); required.
	Log *slog.Logger
	// Users resolves the provider identity to a user; required.
	Users *user.Service
	// Codes issues the login code; required.
	Codes *token.Codes
	// Box seals the provider refresh token kept for revocation (SEC-10);
	// nil when the configuration has no encryption key.
	Box *secure.Box
}

// Callback is the endpoint providers return to: it ties the result to the
// login in progress and to the browser that started it.
type Callback struct {
	reg   provider.Registry
	store store.Store
	clock clock.Clock
	rand  secure.Source
	log   *slog.Logger
	users *user.Service
	codes *token.Codes
	box   *secure.Box
}

// NewCallback returns the callback endpoint.
func NewCallback(c CallbackConfig) *Callback {
	cb := &Callback{reg: c.Registry, store: c.Store, clock: c.Clock, rand: c.Random, log: c.Log, users: c.Users, codes: c.Codes, box: c.Box}
	if cb.rand == nil {
		cb.rand = secure.Default
	}
	return cb
}

// ServeCallback answers a request to /{realm}/callback/{provider}. The realm
// and the provider of the path come from the request context
// (server.FromContext).
func (c *Callback) ServeCallback(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	if !server.AllowMethods(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	if r.Method == http.MethodPost {
		c.handoff(w, r, info)
		return
	}
	q := r.URL.Query()
	state, _ := single(q, "state")
	c.continueLogin(w, r, info, state, func(context.Context) (provider.Callback, error) {
		return provider.Callback{Code: q.Get("code"), Error: q.Get("error")}, nil
	})
}

// handoffLifetime is how long the posted values of a form_post callback wait
// for the browser's GET (Apple's callback).
const handoffLifetime = 60 * time.Second

// handoffBytes is the size of the one-time id: 128 bits.
const handoffBytes = 16

// handoffPayload is what a posted callback keeps: the posted values except
// error_description.
type handoffPayload struct {
	Code    string `json:"code,omitempty"`
	IDToken string `json:"id_token,omitempty"`
	State   string `json:"state"`
	User    string `json:"user,omitempty"`
	Error   string `json:"error,omitempty"`
}

// LogValue implements slog.LogValuer. The code, ID token, state and user JSON
// are secrets or personal data (SEC-13), so only their presence is logged.
func (p handoffPayload) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("code_present", p.Code != ""),
		slog.Bool("id_token_present", p.IDToken != ""),
		slog.Bool("state_present", p.State != ""),
		slog.Bool("user_present", p.User != ""),
		slog.Bool("error_present", p.Error != ""),
	)
}

var _ slog.LogValuer = handoffPayload{}

// handoff answers the cross-site POST of a form_post provider (Apple): the
// cookie is not sent on it, so the posted values wait server-side under a
// one-time id and the browser is sent on with a 303 to the continue path.
func (c *Callback) handoff(w http.ResponseWriter, r *http.Request, info server.Info) {
	ctx, realm := r.Context(), info.Realm
	if err := r.ParseForm(); err != nil {
		c.logRefusal(ctx, realm, "the posted form cannot be read")
		pages.Page(w, r, realm, web.Page{Kind: web.PageError, Status: http.StatusBadRequest, MessageID: "error.invalid_request"})
		return
	}
	state, ok := single(r.PostForm, "state")
	if !ok || state == "" {
		c.logRefusal(ctx, realm, "the posted callback has no single state")
		pages.Page(w, r, realm, expiredPage)
		return
	}
	// Only a login in progress of this realm, of the provider of the path and
	// of a provider that returns by form POST may have its values stored
	// (SEC-23). Anything else stores nothing.
	row, err := c.take(ctx, realm, state)
	switch {
	case errors.Is(err, errRequestGone):
		c.logRefusal(ctx, realm, "the posted callback names no login in progress")
		pages.Page(w, r, realm, expiredPage)
		return
	case err != nil:
		c.readFailure(w, r, realm, err)
		return
	}
	if info.Provider != row.Provider || !c.postsForm(realm.Name, row.Provider) {
		c.logRefusal(ctx, realm, "the posted callback is not a form POST of the login's provider")
		pages.Page(w, r, realm, expiredPage)
		return
	}
	p := r.PostForm
	body, _ := json.Marshal(handoffPayload{
		Code: p.Get("code"), IDToken: p.Get("id_token"), State: state, User: p.Get("user"), Error: p.Get("error"),
	}) // plain strings: Marshal cannot fail
	id, err := secure.Token(c.rand, handoffBytes)
	if err == nil {
		err = c.store.Write(ctx, func(tx store.Tx) error {
			return tx.Handoffs().Create(ctx, store.Handoff{
				IDHash: secure.HashOf(id), AuthRequestID: store.AuthRequestID(state),
				Payload: string(body), ExpiresAt: c.clock.Now().Add(handoffLifetime),
			})
		})
	}
	if err != nil {
		c.log.ErrorContext(ctx, "storing the callback handoff failed", "realm", string(realm.Name), "err", err)
		pages.Page(w, r, realm, web.Page{Kind: web.PageError, Status: http.StatusInternalServerError, MessageID: "error.server"})
		return
	}
	q := url.Values{"id": {id}, "state": {state}}
	w.Header().Set("Location", realm.EndpointPath(config.EndpointCallback, info.Provider)+"/continue?"+q.Encode())
	w.WriteHeader(http.StatusSeeOther)
}

// postsForm reports whether the adapter of the provider returns its result by
// form POST.
func (c *Callback) postsForm(realm config.RealmName, key config.ProviderKey) bool {
	a, ok := c.reg.Get(realm, key)
	if !ok {
		return false
	}
	fp, ok := a.(provider.FormPoster)
	return ok && fp.FormPost()
}

// readFailure answers a store failure while the login is read: 503 for an
// unavailable store, 500 for anything else.
func (c *Callback) readFailure(w http.ResponseWriter, r *http.Request, realm *config.Realm, err error) {
	c.log.ErrorContext(r.Context(), "reading the login failed", "realm", string(realm.Name), "err", err)
	status := http.StatusInternalServerError
	if errors.Is(err, store.ErrUnavailable) {
		status = http.StatusServiceUnavailable
	}
	pages.Page(w, r, realm, web.Page{Kind: web.PageError, Status: status, MessageID: "error.server"})
}

// ServeContinue answers the browser's GET to the continue path after a
// handoff: the same checks as any callback, then the stored values are taken
// once.
func (c *Callback) ServeContinue(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	if !server.AllowMethods(w, r, http.MethodGet) {
		return
	}
	q := r.URL.Query()
	state, _ := single(q, "state")
	id, _ := single(q, "id")
	c.continueLogin(w, r, info, state, func(ctx context.Context) (provider.Callback, error) {
		var h store.Handoff
		err := c.store.Write(ctx, func(tx store.Tx) error {
			h = store.Handoff{} // a run that is run again starts with no result
			var err error
			h, err = tx.Handoffs().Take(ctx, secure.HashOf(id), c.clock.Now())
			return err
		})
		if err != nil {
			return provider.Callback{}, err
		}
		var p handoffPayload
		if json.Unmarshal([]byte(h.Payload), &p) != nil || !secure.Equal(p.State, state) {
			return provider.Callback{}, errHandoffRefused
		}
		return provider.Callback{Code: p.Code, IDToken: p.IDToken, User: p.User, Error: p.Error}, nil
	})
}

// errHandoffRefused means the stored values belong to another login.
var errHandoffRefused = errors.New("oidc: the handoff is for another login")

// errRequestGone means the state names no login that this realm can continue.
var errRequestGone = errors.New("oidc: the login is unknown, expired or not of this realm")

// continueLogin checks a provider's result against the login in progress and
// the browser, then hands it to the adapter. The state cookie is deleted
// whatever the outcome.
func (c *Callback) continueLogin(w http.ResponseWriter, r *http.Request, info server.Info, state string, result func(context.Context) (provider.Callback, error)) {
	ctx, realm := r.Context(), info.Realm
	if state == "" {
		c.logRefusal(ctx, realm, "the callback has no single state")
		pages.Page(w, r, realm, expiredPage)
		return
	}
	http.SetCookie(w, deletedStateCookie(realm, state))

	row, err := c.take(ctx, realm, state)
	switch {
	case errors.Is(err, errRequestGone):
		c.logRefusal(ctx, realm, "the login is unknown or expired")
		pages.Page(w, r, realm, expiredPage)
		return
	case err != nil:
		c.readFailure(w, r, realm, err)
		return
	}
	mode, _ := ParseResponseMode(row.ResponseMode)
	if mode == "" {
		mode = ModeQuery
	}
	fail := func(code, description string) {
		Deliver(w, r, mode, row.RedirectURI, (&RedirectError{
			Err: Error{Code: code, Description: description}, Mode: mode, RedirectURI: row.RedirectURI, State: row.ClientState,
		}).Values(realm.Issuer()))
	}

	if ck, err := r.Cookie(StateCookieName(state)); err != nil || !secure.Equal(ck.Value, state) {
		c.logRefusal(ctx, realm, "the state cookie is missing or does not match")
		fail("access_denied", "the login does not belong to this browser")
		return
	}
	if info.Provider != row.Provider {
		c.logRefusal(ctx, realm, "the callback path names another provider than the login")
		fail("access_denied", "the result came from another provider than the login")
		return
	}
	cb, err := result(ctx)
	if err != nil {
		c.logRefusal(ctx, realm, "the handoff is unknown, used or expired")
		fail("access_denied", "the result cannot be tied to this login")
		return
	}
	adapter, ok := c.reg.Get(realm.Name, row.Provider)
	if !ok {
		code, description := provider.MapError(provider.ErrUnavailable)
		fail(code, description)
		return
	}
	identity, err := adapter.Exchange(ctx, cb, row.ProviderPKCEVerifier, row.ProviderNonce)
	if err != nil {
		code, description := provider.MapError(err)
		c.log.InfoContext(ctx, "the provider login failed", "realm", string(realm.Name),
			"provider", string(row.Provider), "error", code, "err", err)
		fail(code, description)
		return
	}
	code, ssoCookie, err := c.complete(ctx, realm, row, identity, ssoValueOf(r, realm))
	if errors.Is(err, token.ErrLoginGone) {
		// Another callback of this login completed first (SEC-28): the login
		// is over, so the answer is the page of a request that is not in progress.
		c.logRefusal(ctx, realm, "the login was completed by another callback")
		pages.Page(w, r, realm, expiredPage)
		return
	}
	if err != nil {
		var e Error
		if !errors.As(err, &e) {
			e = Error{Code: "server_error", Description: "the login failed"}
		}
		c.log.InfoContext(ctx, "the login was not completed", "realm", string(realm.Name),
			"provider", string(row.Provider), "error", e.Code)
		fail(e.Code, e.Description)
		return
	}
	if ssoCookie != nil {
		http.SetCookie(w, ssoCookie)
	}
	p := url.Values{"code": {code}, "iss": {realm.Issuer()}}
	if row.ClientState != "" {
		p.Set("state", row.ClientState)
	}
	Deliver(w, r, mode, row.RedirectURI, p)
}

// complete turns the provider's identity into a login code: max_age is
// checked against the provider's auth_time, the user is found, linked or
// created, and the code is issued together with the deletion of the login row
// (SEC-28). A login of a client in a realm with single sign-on also starts a
// browser session: the code carries its hash, the session is stored after the
// code is issued, and the cookie that carries it is returned (FR-45). prev is
// the value of the browser's earlier session cookie. A failure is an Error to
// deliver, or token.ErrLoginGone when the login was completed by another callback.
func (c *Callback) complete(ctx context.Context, realm *config.Realm, row store.AuthRequest, id provider.Identity, prev string) (string, *http.Cookie, error) {
	now := c.clock.Now()
	authTime := id.AuthTime
	if authTime.IsZero() {
		authTime = now // the time the callback completed
	}
	if row.MaxAge != nil && now.Sub(authTime) > *row.MaxAge {
		return "", nil, Error{Code: "login_required", Description: "the provider's sign-in is older than max_age"}
	}
	sealed, err := c.sealToken(realm.Providers[row.Provider], id)
	if err != nil {
		return "", nil, err
	}
	u, err := c.users.Resolve(ctx, user.ResolveInput{
		Realm: realm, ProviderKey: row.Provider, Provider: realm.Providers[row.Provider], Identity: id,
		SealedProviderToken: sealed,
	})
	switch {
	case errors.Is(err, user.ErrDisabled), errors.Is(err, user.ErrRefused):
		return "", nil, Error{Code: "access_denied", Description: "the login was refused"}
	case err != nil:
		return "", nil, err
	}
	start, err := c.newSSOStart(realm, row.ClientID)
	if err != nil {
		return "", nil, err
	}
	in := token.IssueInput{
		Realm: realm, Client: realm.Clients[row.ClientID], User: token.UserID(u.ID), RedirectURI: row.RedirectURI,
		CodeChallenge: row.CodeChallenge, Nonce: row.Nonce, AuthTime: authTime, Login: row.ID,
	}
	if start != nil {
		in.SSOIDHash = start.hash
	}
	code, err := c.codes.Issue(ctx, in)
	if err != nil || start == nil {
		return code, nil, err
	}
	if err := c.storeSession(ctx, realm, start, prev, row.Provider, id.Subject, store.UserID(u.ID), authTime); err != nil {
		return "", nil, err
	}
	return code, ssoCookie(realm, start.value), nil
}

// sealToken seals the provider refresh token of a login for storage; it is
// empty when the provider keeps none (store_refresh_token false) or returned
// none.
func (c *Callback) sealToken(p *config.Provider, id provider.Identity) (string, error) {
	if !p.StoreRefreshToken || id.RefreshToken == "" {
		return "", nil
	}
	if c.box == nil {
		return "", errors.New("oidc: store_refresh_token needs an encryption key")
	}
	return c.box.Seal([]byte(id.RefreshToken))
}

var expiredPage = web.Page{Kind: web.PageError, Status: http.StatusBadRequest, MessageID: "error.request_expired"}

func (c *Callback) logRefusal(ctx context.Context, realm *config.Realm, reason string) {
	c.log.InfoContext(ctx, "callback refused", "realm", string(realm.Name), "reason", reason)
}

// take reads the login of the state. A login that is unknown, expired, of
// another realm or completed gives errRequestGone. The row is not deleted here:
// a login that fails keeps it, so that a replayed handoff still finds it to
// answer access_denied. A completed login loses its row when its code is
// issued (complete), and the hourly job removes expired rows.
func (c *Callback) take(ctx context.Context, realm *config.Realm, state string) (store.AuthRequest, error) {
	var row store.AuthRequest
	err := c.store.Read(ctx, func(tx store.Tx) error {
		req, err := tx.AuthRequests().Get(ctx, store.AuthRequestID(state))
		if errors.Is(err, store.ErrNotFound) {
			return errRequestGone
		}
		if err != nil {
			return err
		}
		rid, err := tx.Realms().Find(ctx, realm.Name)
		if errors.Is(err, store.ErrNotFound) || (err == nil && rid != req.RealmID) {
			return errRequestGone
		}
		if err != nil {
			return err
		}
		if !c.clock.Now().Before(req.ExpiresAt) {
			return errRequestGone
		}
		row = req
		return nil
	})
	if err != nil {
		return store.AuthRequest{}, err
	}
	if _, ok := realm.Clients[row.ClientID]; !ok {
		return store.AuthRequest{}, errRequestGone
	}
	return row, nil
}

// deletedStateCookie ends the state cookie of a login: the same name and path
// as the cookie that was set, with no value.
func deletedStateCookie(realm *config.Realm, state string) *http.Cookie {
	return &http.Cookie{
		Name: StateCookieName(state), Path: realm.StateCookiePath(), MaxAge: -1,
		HttpOnly: true, Secure: stateCookieSecure(realm), SameSite: http.SameSiteLaxMode,
	}
}
