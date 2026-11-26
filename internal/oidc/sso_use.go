package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/token"
)

// noSessionError is the answer to prompt=none without a usable browser session.
var noSessionError = Error{Code: "login_required", Description: "there is no session to reuse"}

// sessionState is what the browser session of a request's cookie means for the
// request (Single sign-on session, FR-45).
type sessionState int

const (
	// sessionUsable: the request is answered from the session.
	sessionUsable sessionState = iota + 1
	// sessionUnusable: the session itself cannot be used (it is missing, expired,
	// its user is disabled or gone, its identity or provider is gone, or the realm's
	// sso is off). The cookie is deleted.
	sessionUnusable
	// sessionNotForThisRequest: the session is fine, but this request's own
	// conditions (the client's sso, the prompt, max_age or the provider hint) rule
	// its use out. The cookie and the row are left alone; the request goes on as without a session.
	sessionNotForThisRequest
)

// silentLogin answers an authorization request from the browser session of its
// cookie when the session may be used (Single sign-on session: Use; FR-45): with a
// login code, which is delivered, and true is returned. A prompt=none request that
// cannot use it is answered login_required and true is returned too. Otherwise
// false is returned and the request goes on as without a session; a cookie that names an
// unusable session is deleted on the way.
func (a *Authorize) silentLogin(w http.ResponseWriter, r *http.Request, req AuthRequest, v url.Values) bool {
	ctx, realm := r.Context(), req.Realm
	value := ssoValueOf(r, realm)
	if value == "" {
		return a.noSession(w, r, req)
	}
	sess, rid, state, err := a.readSession(ctx, req, value)
	if err != nil {
		a.log.ErrorContext(ctx, "reading the browser session failed", "realm", string(realm.Name), "err", err)
		a.deliverError(w, r, a.requestError(req, Error{Code: "server_error", Description: "the login could not be started"}))
		return true
	}
	switch state {
	case sessionUnusable:
		http.SetCookie(w, deletedSSOCookie(realm))
		return a.noSession(w, r, req)
	case sessionNotForThisRequest:
		return a.noSession(w, r, req)
	}
	if req.PromptNone && a.foreignHint(realm, v, sess.UserID) {
		a.deliverError(w, r, a.requestError(req, noSessionError))
		return true
	}
	// The session is moved on before the code is issued: a session that a logout
	// deleted since it was read gives no code.
	now := a.clock.Now()
	err = a.store.Write(ctx, func(tx store.Tx) error {
		return tx.SSOSessions().Touch(ctx, rid, sess.IDHash, now, ssoExpiry(realm.SSO, sess.CreatedAt, now))
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.SetCookie(w, deletedSSOCookie(realm))
		return a.noSession(w, r, req)
	case err != nil:
		a.log.ErrorContext(ctx, "moving the browser session on failed", "realm", string(realm.Name), "err", err)
		a.deliverError(w, r, a.requestError(req, Error{Code: "server_error", Description: "the login could not be completed"}))
		return true
	}
	a.answerFromSession(w, r, req, value, sess)
	return true
}

// noSession answers a request that is not answered from a browser session: the
// prompt=none request gets login_required, any other one goes on as without a session.
func (a *Authorize) noSession(w http.ResponseWriter, r *http.Request, req AuthRequest) bool {
	if req.PromptNone {
		a.deliverError(w, r, a.requestError(req, noSessionError))
		return true
	}
	return false
}

// requestError is a redirect error of the request, with its mode, redirect URI and
// state.
func (a *Authorize) requestError(req AuthRequest, e Error) *RedirectError {
	return &RedirectError{Err: e, Mode: req.ResponseMode, RedirectURI: req.RedirectURI, State: req.State}
}

// readSession reads the browser session of value and says what it means for the
// request. The session's own conditions come first (the realm's sso, the row, its
// expiry, the provider, the user and the identity); the request's conditions
// (the client's sso, the prompt, max_age and the provider hint) come after them.
// A session that is not usable is not an error.
func (a *Authorize) readSession(ctx context.Context, req AuthRequest, value string) (store.SSOSession, store.RealmID, sessionState, error) {
	realm := req.Realm
	if !realm.SSO.Enabled {
		return store.SSOSession{}, "", sessionUnusable, nil
	}
	now := a.clock.Now()
	var (
		sess  store.SSOSession
		rid   store.RealmID
		state = sessionUnusable
	)
	err := a.store.Read(ctx, func(tx store.Tx) error {
		state = sessionUnusable
		var err error
		rid, err = tx.Realms().Find(ctx, realm.Name)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		sess, err = tx.SSOSessions().Find(ctx, rid, secure.HashOf(value))
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !now.Before(sess.ExpiresAt) {
			return nil
		}
		if p, has := realm.Providers[sess.Provider]; !has || !p.Enabled {
			return nil
		}
		u, err := tx.Users().Get(ctx, rid, sess.UserID)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !u.DisabledAt.IsZero() {
			return nil
		}
		idents, err := tx.Identities().ListByUser(ctx, rid, sess.UserID)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(idents, func(i store.Identity) bool { return i.ID == sess.IdentityID }) {
			return nil
		}
		state = sessionNotForThisRequest
		return nil
	})
	if err != nil {
		return store.SSOSession{}, "", sessionUnusable, err
	}
	if state != sessionNotForThisRequest {
		return store.SSOSession{}, "", sessionUnusable, nil
	}
	if !req.Client.SSO || req.Prompt != "" || (req.Hint != "" && config.ProviderKey(req.Hint) != sess.Provider) ||
		(req.MaxAge != nil && *req.MaxAge < now.Sub(sess.AuthTime)) {
		return sess, rid, sessionNotForThisRequest, nil
	}
	return sess, rid, sessionUsable, nil
}

// foreignHint reports whether the request's id_token_hint verifies and names
// another user than uid. A hint that does not verify, or a repeated one, is
// ignored (FR-45): it is not a foreign hint.
func (a *Authorize) foreignHint(realm *config.Realm, v url.Values, uid store.UserID) bool {
	raw, ok := single(v, "id_token_hint")
	if !ok || raw == "" || a.hints == nil {
		return false
	}
	claims, err := a.hints.IDTokenHint(realm, raw)
	if err != nil {
		return false
	}
	return string(claims.Sub) != string(uid)
}

// answerFromSession answers the request with a login code of the session: the
// session's auth_time and browser session, and a new token session. The session's
// cookie is set again (FR-45); its last use and expiry were moved on before.
func (a *Authorize) answerFromSession(w http.ResponseWriter, r *http.Request, req AuthRequest, value string, sess store.SSOSession) {
	ctx, realm := r.Context(), req.Realm
	code, err := a.codes.Issue(ctx, token.IssueInput{
		Realm: realm, Client: req.Client, User: token.UserID(sess.UserID), RedirectURI: req.RedirectURI,
		CodeChallenge: req.CodeChallenge, Nonce: req.Nonce, AuthTime: sess.AuthTime, SSOIDHash: sess.IDHash,
	})
	if err != nil {
		a.log.ErrorContext(ctx, "issuing the code of a browser session failed", "realm", string(realm.Name), "err", err)
		a.deliverError(w, r, a.requestError(req, Error{Code: "server_error", Description: "the login could not be completed"}))
		return
	}
	a.log.LogAttrs(ctx, slog.LevelInfo, "authorization answered from the browser session",
		slog.String("realm", string(realm.Name)), slog.String("client", string(req.ClientID)))
	http.SetCookie(w, ssoCookie(realm, value))
	p := url.Values{"code": {code}, "iss": {realm.Issuer()}}
	if req.State != "" {
		p.Set("state", req.State)
	}
	Deliver(w, r, req.ResponseMode, req.RedirectURI, p)
}
