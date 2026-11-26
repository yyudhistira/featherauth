package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/token"
	"github.com/yyudhistira/featherauth/internal/user"
	"github.com/yyudhistira/featherauth/internal/web"
)

// hintVerifier is what the logout endpoint needs of the token verifier.
type hintVerifier interface {
	IDTokenHint(r *config.Realm, raw string) (token.HintClaims, error)
}

var _ hintVerifier = (*token.Verifier)(nil)

// sessionsRevoker is what the bearer logout needs to end the sessions of a
// user: all of them (all_sessions) or one (session).
type sessionsRevoker interface {
	RevokeSessions(ctx context.Context, actor string, realm config.RealmName, id store.UserID) (int, error)
	RevokeSession(ctx context.Context, actor string, realm config.RealmName, id store.UserID, session store.SessionID) (int, error)
}

var _ sessionsRevoker = (*user.Manager)(nil)

// LogoutConfig is what the logout endpoint needs.
type LogoutConfig struct {
	// Verifier checks ID token hints; required.
	Verifier *token.Verifier
	// Bearer authenticates a bearer access token; required.
	Bearer *BearerAuth
	// Store holds the sessions; required.
	Store store.Store
	// Users ends every session of a user and audits it (all_sessions); required.
	Users *user.Manager
	// Clock is the source of time; required.
	Clock clock.Clock
	// Rand is the source of the ids of the logout notifications; required.
	Rand secure.Source
	// Log is the service logger (logx); required.
	Log *slog.Logger
}

// Logout is the logout endpoint (RP-Initiated Logout 1.0, and the app requests
// of "Ending a session"): it revokes the session the request names.
type Logout struct {
	hints  hintVerifier
	bearer *BearerAuth
	store  store.Store
	users  sessionsRevoker
	clock  clock.Clock
	rand   secure.Source
	log    *slog.Logger
}

// NewLogout returns the logout endpoint.
func NewLogout(c LogoutConfig) *Logout {
	return &Logout{hints: c.Verifier, bearer: c.Bearer, store: c.Store, users: c.Users, clock: c.Clock, rand: c.Rand, log: c.Log}
}

var _ http.Handler = (*Logout)(nil)

// ServeHTTP answers a GET or a POST of /{realm}/logout. A POST with a
// non-empty refresh_token is the refresh token request, else a POST with an
// Authorization header of the Bearer scheme is the bearer request (both answered 204 or an OAuth error); every other
// request is RP-initiated and is answered with a redirect or a page.
func (l *Logout) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	if !server.AllowMethods(w, r, http.MethodGet, http.MethodPost) {
		return
	}
	var v url.Values
	if r.Method == http.MethodGet {
		v = r.URL.Query()
	} else {
		if err := r.ParseForm(); err != nil {
			pages.Page(w, r, info.Realm, web.Page{Kind: web.PageError, Status: http.StatusBadRequest, MessageID: "error.invalid_request"})
			return
		}
		v = r.PostForm
		switch {
		case len(v["refresh_token"]) > 1:
			WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "refresh_token must not be repeated"})
			return
		case v.Get("refresh_token") != "":
			l.byRefreshToken(w, r, info, v)
			return
		case isBearer(r.Header.Get("Authorization")):
			l.byBearer(w, r, info, v)
			return
		}
	}
	l.rpInitiated(w, r, info, v)
}

// refuse answers an RP-initiated request that cannot be trusted: the error
// page, nothing revoked and no redirect.
func (l *Logout) refuse(w http.ResponseWriter, r *http.Request, realm *config.Realm, reason string) {
	l.log.InfoContext(r.Context(), "logout refused", "realm", string(realm.Name), "reason", reason)
	pages.Page(w, r, realm, web.Page{Kind: web.PageError, Status: http.StatusBadRequest, MessageID: "error.logout_refused"})
}

// standardReturnParam is the return URL parameter of RP-Initiated Logout 1.0;
// any other name in logout.redirect_params is a legacy name.
const standardReturnParam = "post_logout_redirect_uri"

func (l *Logout) rpInitiated(w http.ResponseWriter, r *http.Request, info server.Info, v url.Values) {
	realm := info.Realm
	params := info.Snapshot.Server().Logout.RedirectParams
	for _, name := range append([]string{"id_token_hint", "client_id", "state"}, params...) {
		if len(v[name]) > 1 {
			l.refuse(w, r, realm, "a parameter is repeated")
			return
		}
	}
	// The standard parameter counts first, so a request that carries it and a
	// legacy one is read as the standard one.
	var returnURL string
	standard := false
	if slices.Contains(params, standardReturnParam) {
		returnURL = v.Get(standardReturnParam)
		standard = returnURL != ""
	}
	for _, name := range params {
		if returnURL != "" {
			break
		}
		returnURL = v.Get(name)
	}
	clientID := v.Get("client_id")
	hint := v.Get("id_token_hint")

	var sid token.SessionID
	revoke := false
	if hint != "" {
		claims, err := l.hints.IDTokenHint(realm, hint)
		if err != nil {
			l.refuse(w, r, realm, "the id_token_hint fails verification")
			return
		}
		if clientID != "" && clientID != claims.Aud {
			l.refuse(w, r, realm, "the client_id does not match the id_token_hint")
			return
		}
		clientID, sid, revoke = claims.Aud, claims.Sid, true
	}

	if returnURL != "" && clientID == "" && standard {
		// Neither a hint nor a client_id: RP-Initiated Logout 1.0 does not
		// confirm the target, so only a legacy parameter is redirected.
		returnURL = ""
	}
	if returnURL != "" {
		registered := false
		if clientID != "" {
			if cl, ok := realm.Clients[config.ClientID(clientID)]; ok {
				for _, u := range cl.PostLogoutURIs() {
					registered = registered || u == returnURL
				}
			}
		} else {
			_, registered = realm.PostLogoutURIRegistered(returnURL)
		}
		if !registered {
			l.refuse(w, r, realm, "the return URL is not registered")
			return
		}
	}

	if revoke {
		if err := l.revokeSession(r, realm, sid); err != nil {
			l.pageFailure(w, r, realm, err)
			return
		}
	}
	// A logout with the browser's cookie ends its browser session and clears the
	// cookie, with or without a hint (FR-45). Without a hint no token session ends.
	if value := ssoValueOf(r, realm); value != "" {
		if err := l.endBrowserSession(r.Context(), realm, value); err != nil {
			l.pageFailure(w, r, realm, err)
			return
		}
		http.SetCookie(w, deletedSSOCookie(realm))
	}
	l.log.InfoContext(r.Context(), "logout", "realm", string(realm.Name), "client", clientID, "revoked", revoke)
	if returnURL == "" {
		pages.Page(w, r, realm, web.Page{Kind: web.PageSignedOut})
		return
	}
	if state := v.Get("state"); state != "" {
		sep := "?"
		if strings.Contains(returnURL, "?") {
			sep = "&"
		}
		returnURL += sep + url.Values{"state": {state}}.Encode()
	}
	redirect(w, returnURL)
}

func (l *Logout) byRefreshToken(w http.ResponseWriter, r *http.Request, info server.Info, v url.Values) {
	realm := info.Realm
	client, _, err := token.AuthenticateClient(realm, info.Snapshot.Secrets(), v, r.Header.Get("Authorization"))
	if err != nil {
		logClientAuthFailure(r.Context(), l.log, err)
		if !writeClientAuthError(w, realm, err) {
			l.apiFailure(w, r, err)
		}
		return
	}
	cid := clientIDOf(realm, client)
	// The token is looked up in a read transaction. The write happens only for
	// a token of this client whose session still has a live refresh token
	// (SEC-34): nothing is written for the other answers.
	var (
		rid     store.RealmID
		session store.SessionID
		refused bool
		live    bool
	)
	err = l.store.Read(r.Context(), func(tx store.Tx) error {
		var err error
		rid, err = tx.Realms().Find(r.Context(), realm.Name)
		if errors.Is(err, store.ErrNotFound) {
			refused = true
			return nil
		}
		if err != nil {
			return err
		}
		rt, err := tx.RefreshTokens().FindByHash(r.Context(), rid, secure.HashOf(v.Get("refresh_token")))
		if errors.Is(err, store.ErrNotFound) || (err == nil && rt.ClientID != cid) {
			// Another client's token is refused and left alone.
			refused = true
			return nil
		}
		if err != nil {
			return err
		}
		session = rt.SessionID
		live, err = tx.RefreshTokens().SessionLive(r.Context(), rid, session)
		return err
	})
	if err == nil && !refused && live {
		err = l.store.Write(r.Context(), func(tx store.Tx) error {
			ended, err := tx.RefreshTokens().RevokeSession(r.Context(), rid, session, l.clock.Now())
			if err != nil {
				return err
			}
			return store.QueueLogouts(r.Context(), tx, realm, rid, ended.Sessions, l.clock, l.rand)
		})
	}
	switch {
	case err != nil:
		l.apiFailure(w, r, err)
	case refused:
		l.log.InfoContext(r.Context(), "logout refused", "realm", string(realm.Name), "reason", "the refresh token is not valid for this client")
		WriteJSONError(w, Error{Code: token.CodeInvalidGrant, Description: "invalid refresh token"})
	default:
		l.noContent(w, r, realm, "refresh_token")
	}
}

func (l *Logout) byBearer(w http.ResponseWriter, r *http.Request, info server.Info, v url.Values) {
	claims, _, berr := l.bearer.Bearer(r, info.Realm, config.EndpointLogout)
	if berr != nil {
		switch berr.Status {
		case http.StatusServiceUnavailable, http.StatusInternalServerError:
			l.log.WarnContext(r.Context(), "logout: the bearer check failed", "status", berr.Status)
			WriteJSONError(w, *berr)
		default:
			WriteBearerError(w, *berr, nil)
		}
		return
	}
	all, ok := allSessions(w, v)
	if !ok {
		return
	}
	session, ok := sessionField(w, v)
	if !ok {
		return
	}
	if all && session != "" {
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "session and all_sessions cannot be used together"})
		return
	}
	if all {
		l.signOutEverywhere(w, r, info.Realm, claims)
		return
	}
	if session != "" {
		l.signOutSession(w, r, info.Realm, claims, store.SessionID(session))
		return
	}
	if err := l.revokeSession(r, info.Realm, claims.Sid); err != nil {
		l.apiFailure(w, r, err)
		return
	}
	l.noContent(w, r, info.Realm, "bearer")
}

// allSessions reads the form field all_sessions of the bearer logout: absent
// or empty is false (the request without the field), "true" is true, a repeated field or any
// other value is invalid_request, answered here (ok is false).
func allSessions(w http.ResponseWriter, v url.Values) (all, ok bool) {
	vals := v["all_sessions"]
	switch {
	case len(vals) > 1:
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "all_sessions must not be repeated"})
		return false, false
	case len(vals) == 0 || vals[0] == "":
		return false, true
	case vals[0] == "true":
		return true, true
	}
	WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "all_sessions must be true"})
	return false, false
}

// sessionField reads the form field session of the bearer logout: the id of
// one session of the token's user. Absent or empty means none; a repeated
// field is invalid_request, answered here (ok is false).
func sessionField(w http.ResponseWriter, v url.Values) (session string, ok bool) {
	vals := v["session"]
	switch {
	case len(vals) > 1:
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "session must not be repeated"})
		return "", false
	case len(vals) == 0:
		return "", true
	}
	return vals[0], true
}

// signOutSession ends the session named by the field session when it is a
// session of the token's user, for a client with allow_session_management. A
// session that is not the user's is invalid_request and nothing is revoked; a
// session already ended answers 204 with no audit row.
func (l *Logout) signOutSession(w http.ResponseWriter, r *http.Request, realm *config.Realm, claims token.AccessClaims, session store.SessionID) {
	if !mayManageSessions(realm, claims.Azp) {
		refuseSessionManagement(w, r)
		return
	}
	n, err := l.users.RevokeSession(r.Context(), "system", realm.Name, store.UserID(claims.Sub), session)
	switch {
	case errors.Is(err, user.ErrSessionNotFound):
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "session is not a session of this user"})
		return
	case errors.Is(err, user.ErrNotFound), errors.Is(err, store.ErrNotFound):
		WriteBearerError(w, withScheme(r, *invalidToken()), nil) // the user was deleted since the check
		return
	case err != nil:
		l.apiFailure(w, r, err)
		return
	}
	l.log.InfoContext(r.Context(), "logout", "realm", string(realm.Name), "via", "bearer", "sessions", n)
	noStore(w.Header())
	w.WriteHeader(http.StatusNoContent)
}

// signOutEverywhere ends every session of the token's user in the realm (the
// field all_sessions=true), for a client with allow_session_management. A
// client removed since the token was issued counts as without the option.
func (l *Logout) signOutEverywhere(w http.ResponseWriter, r *http.Request, realm *config.Realm, claims token.AccessClaims) {
	if !mayManageSessions(realm, claims.Azp) {
		refuseSessionManagement(w, r)
		return
	}
	n, err := l.users.RevokeSessions(r.Context(), "system", realm.Name, store.UserID(claims.Sub))
	switch {
	case errors.Is(err, user.ErrNotFound), errors.Is(err, store.ErrNotFound):
		WriteBearerError(w, withScheme(r, *invalidToken()), nil) // the user was deleted since the check
		return
	case err != nil:
		l.apiFailure(w, r, err)
		return
	}
	l.log.InfoContext(r.Context(), "logout", "realm", string(realm.Name), "via", "bearer", "all_sessions", true, "sessions", n)
	noStore(w.Header())
	w.WriteHeader(http.StatusNoContent)
}

func (l *Logout) noContent(w http.ResponseWriter, r *http.Request, realm *config.Realm, how string) {
	l.log.InfoContext(r.Context(), "logout", "realm", string(realm.Name), "via", how, "revoked", true)
	noStore(w.Header())
	w.WriteHeader(http.StatusNoContent)
}

// revokeSession revokes every refresh token of the session; a realm the store
// does not know yet has none.
func (l *Logout) revokeSession(r *http.Request, realm *config.Realm, sid token.SessionID) error {
	ctx := r.Context()
	err := l.store.Write(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, realm.Name)
		if err != nil {
			return err
		}
		ended, err := tx.RefreshTokens().RevokeSession(ctx, rid, store.SessionID(sid), l.clock.Now())
		if err != nil {
			return err
		}
		return store.QueueLogouts(ctx, tx, realm, rid, ended.Sessions, l.clock, l.rand)
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// endBrowserSession deletes the browser session whose cookie value is value, in
// the realm. A realm the store does not know has no session to end.
func (l *Logout) endBrowserSession(ctx context.Context, realm *config.Realm, value string) error {
	return l.store.Write(ctx, func(tx store.Tx) error {
		rid, err := tx.Realms().Find(ctx, realm.Name)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return tx.SSOSessions().Delete(ctx, rid, secure.HashOf(value))
	})
}

// apiFailure answers a store failure of an app request: 503 for an
// unavailable store, 500 for anything else.
func (l *Logout) apiFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrUnavailable) {
		l.log.WarnContext(r.Context(), "logout: the store is unavailable", "err", err)
		WriteJSONError(w, Error{Code: "temporarily_unavailable", Description: "the service is temporarily unavailable", Status: http.StatusServiceUnavailable})
		return
	}
	l.log.ErrorContext(r.Context(), "logout failed", "err", err)
	WriteJSONError(w, Error{Code: "server_error", Description: "the request could not be completed", Status: http.StatusInternalServerError})
}

// pageFailure is apiFailure for a browser request.
func (l *Logout) pageFailure(w http.ResponseWriter, r *http.Request, realm *config.Realm, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, store.ErrUnavailable) {
		status = http.StatusServiceUnavailable
		l.log.WarnContext(r.Context(), "logout: the store is unavailable", "err", err)
	} else {
		l.log.ErrorContext(r.Context(), "logout failed", "err", err)
	}
	pages.Page(w, r, realm, web.Page{Kind: web.PageError, Status: status, MessageID: "error.server"})
}

// clientIDOf returns the id of a client of the realm.
func clientIDOf(realm *config.Realm, cl *config.Client) config.ClientID {
	for id, c := range realm.Clients {
		if c == cl {
			return id
		}
	}
	return ""
}

// isBearer reports whether an Authorization header uses the Bearer scheme or the
// DPoP scheme, which counts the same (FR-44; case-insensitive, RFC 7235).
func isBearer(h string) bool {
	scheme, _, _ := strings.Cut(h, " ")
	return strings.EqualFold(scheme, "Bearer") || strings.EqualFold(scheme, "DPoP")
}
