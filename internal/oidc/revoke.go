package oidc

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"net/http"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/token"
)

// RevokeConfig is what the revocation endpoint needs.
type RevokeConfig struct {
	// Verifier checks access tokens; required.
	Verifier *token.Verifier
	// Store holds the sessions; required.
	Store store.Store
	// Clock is the source of time; required.
	Clock clock.Clock
	// Rand is the source of the ids of the logout notifications; required.
	Rand secure.Source
	// Log is the service logger (logx); required.
	Log *slog.Logger
}

// Revoke is the revocation endpoint (RFC 7009, FR-38): a refresh token or an
// access token of the authenticated client ends its session; any other token
// changes nothing.
type Revoke struct {
	verifier accessVerifier
	store    store.Store
	clock    clock.Clock
	rand     secure.Source
	log      *slog.Logger
}

// NewRevoke returns the revocation endpoint. Every field of the config is
// required, as for the other endpoints; none is checked for nil.
func NewRevoke(c RevokeConfig) *Revoke {
	return &Revoke{verifier: c.Verifier, store: c.Store, clock: c.Clock, rand: c.Rand, log: c.Log}
}

var _ http.Handler = (*Revoke)(nil)

// ServeHTTP answers a POST of /{realm}/revoke. The request is read as the
// token endpoint reads it: a form, client authentication, the origin check,
// then the token.
func (rv *Revoke) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	if !server.AllowMethods(w, r, http.MethodPost, http.MethodOptions) {
		return
	}
	if r.Method == http.MethodOptions {
		// A preflight is answered by the CORS middleware; any other OPTIONS
		// request is not a revocation.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "the request must be application/x-www-form-urlencoded"})
		return
	}
	if err := r.ParseForm(); err != nil {
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "the request body cannot be read"})
		return
	}
	// Only the body counts: a secret or a token in the URL is not accepted.
	form := r.PostForm

	realm := info.Realm
	client, _, err := token.AuthenticateClient(realm, info.Snapshot.Secrets(), form, r.Header.Get("Authorization"))
	if err != nil {
		logClientAuthFailure(r.Context(), rv.log, err)
		if !writeClientAuthError(w, realm, err) {
			rv.apiFailure(w, r, err)
		}
		return
	}
	if !server.AllowOrigin(w, r, client) {
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "origin not allowed for this client"})
		return
	}
	values := form["token"]
	switch {
	case len(values) == 0 || (len(values) == 1 && values[0] == ""):
		// An empty value counts as absent, as in the logout endpoint.
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "token is required"})
		return
	case len(values) > 1:
		WriteJSONError(w, Error{Code: token.CodeInvalidRequest, Description: "token must not be repeated"})
		return
	}

	cid := clientIDOf(realm, client)
	revoked, err := rv.revoke(r.Context(), realm, cid, values[0], form.Get("token_type_hint"))
	if err != nil {
		rv.apiFailure(w, r, err)
		return
	}
	rv.log.InfoContext(r.Context(), "revocation", "realm", string(realm.Name), "client", string(cid), "revoked", revoked)
	noStore(w.Header())
	w.WriteHeader(http.StatusOK)
}

// revoke ends the session the token names for client cid and reports whether
// it did. The token is looked up in a read transaction, and the write happens
// only when the token names a session of the client that still has a refresh
// token that is not revoked (SEC-34); every other token writes nothing.
func (rv *Revoke) revoke(ctx context.Context, realm *config.Realm, cid config.ClientID, raw, hint string) (bool, error) {
	var (
		rid     store.RealmID
		session store.SessionID
		named   bool
		live    bool
	)
	err := rv.store.Read(ctx, func(tx store.Tx) error {
		var err error
		rid, err = tx.Realms().Find(ctx, realm.Name)
		if errors.Is(err, store.ErrNotFound) {
			return nil // a realm the store does not know has no session
		}
		if err != nil {
			return err
		}
		session, named, err = rv.sessionOf(ctx, tx, rid, realm, cid, raw, hint == "access_token")
		if err != nil || !named {
			return err
		}
		live, err = tx.RefreshTokens().SessionLive(ctx, rid, session)
		return err
	})
	if err != nil || !named || !live {
		return false, err
	}
	err = rv.store.Write(ctx, func(tx store.Tx) error {
		ended, err := tx.RefreshTokens().RevokeSession(ctx, rid, session, rv.clock.Now())
		if err != nil {
			return err
		}
		return store.QueueLogouts(ctx, tx, realm, rid, ended.Sessions, rv.clock, rv.rand)
	})
	return err == nil, err
}

// sessionOf returns the session the token names for client cid: a refresh
// token of the client (found by its hash) or an access token whose azp is the
// client (its sid). accessFirst is the order given by token_type_hint; the
// second kind is tried only when the first names nothing.
func (rv *Revoke) sessionOf(ctx context.Context, tx store.Tx, rid store.RealmID, realm *config.Realm, cid config.ClientID, raw string, accessFirst bool) (store.SessionID, bool, error) {
	tries := []func() (store.SessionID, bool, error){
		func() (store.SessionID, bool, error) { return refreshSession(ctx, tx, rid, cid, raw) },
		func() (store.SessionID, bool, error) { return rv.accessSession(realm, cid, raw) },
	}
	if accessFirst {
		tries[0], tries[1] = tries[1], tries[0]
	}
	for _, try := range tries {
		session, named, err := try()
		if err != nil || named {
			return session, named, err
		}
	}
	return "", false, nil
}

// refreshSession names the session of a refresh token issued to client cid.
// An unknown token, or one of another client, names nothing.
func refreshSession(ctx context.Context, tx store.Tx, rid store.RealmID, cid config.ClientID, raw string) (store.SessionID, bool, error) {
	rt, err := tx.RefreshTokens().FindByHash(ctx, rid, secure.HashOf(raw))
	if errors.Is(err, store.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if rt.ClientID != cid {
		return "", false, nil
	}
	return rt.SessionID, true, nil
}

// accessSession names the session of an access token of realm whose azp is
// client cid. A token that does not verify (unknown, expired, an ID token) names
// nothing.
func (rv *Revoke) accessSession(realm *config.Realm, cid config.ClientID, raw string) (store.SessionID, bool, error) {
	claims, err := rv.verifier.Access(realm, raw)
	if err != nil || claims.Azp != string(cid) {
		return "", false, nil
	}
	return store.SessionID(claims.Sid), true, nil
}

// apiFailure answers a store failure of a revocation: 503 for an unavailable
// store, 500 for anything else.
func (rv *Revoke) apiFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrUnavailable) {
		rv.log.WarnContext(r.Context(), "revocation: the store is unavailable", "err", err)
		WriteJSONError(w, Error{Code: "temporarily_unavailable", Description: "the service is temporarily unavailable", Status: http.StatusServiceUnavailable})
		return
	}
	rv.log.ErrorContext(r.Context(), "revocation failed", "err", err)
	WriteJSONError(w, Error{Code: "server_error", Description: "the request could not be completed", Status: http.StatusInternalServerError})
}
