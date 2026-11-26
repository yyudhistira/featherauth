package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/token"
	"github.com/yyudhistira/featherauth/internal/user"
)

// accountDeleter is what the account endpoint needs of the user manager.
type accountDeleter interface {
	Delete(ctx context.Context, actor string, realm config.RealmName, id store.UserID, opts user.DeleteOptions) error
}

var _ accountDeleter = (*user.Manager)(nil)

// AccountConfig is what the account deletion endpoint needs.
type AccountConfig struct {
	// Bearer authenticates the request; required.
	Bearer *BearerAuth
	// Users deletes the user; required.
	Users *user.Manager
	// Clock gives the time the login age is measured against; required.
	Clock clock.Clock
	// Log is the service logger (logx); required.
	Log *slog.Logger
}

// Account is the account deletion endpoint, DELETE /account (FR-13).
type Account struct {
	bearer *BearerAuth
	users  accountDeleter
	clock  clock.Clock
	log    *slog.Logger
}

// NewAccount returns the account deletion endpoint.
func NewAccount(c AccountConfig) *Account {
	return &Account{bearer: c.Bearer, users: c.Users, clock: c.Clock, log: c.Log}
}

var _ http.Handler = (*Account)(nil)

// ServeHTTP answers DELETE /{realm}/account. The checks run in the order of
// FR-13: the bearer token (invalid_token), the client of the token
// (insufficient_scope), the age of the login (insufficient_user_authentication,
// RFC 9470), then the user, which must exist and not be disabled
// (invalid_token); then the user is deleted with a revoke at the provider.
func (a *Account) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	if !server.AllowMethods(w, r, http.MethodDelete) {
		return
	}
	realm := info.Realm
	claims, proof, berr := a.bearer.Claims(r, realm, config.EndpointAccountDelete)
	if berr != nil {
		a.fail(w, r, *berr)
		return
	}
	// A DPoP request is authenticated in full before the endpoint's own checks:
	// its user is looked up and its jti remembered first (SEC-36). A Bearer
	// request keeps the plain order: the checks first, the user after them.
	var usr *store.User
	if proof != nil {
		usr, berr = a.authenticateDPoP(w, r, realm, claims, proof)
		if berr != nil {
			return
		}
	}
	// A client removed since the token was issued counts as not allowed.
	if cl := realm.Clients[config.ClientID(claims.Azp)]; cl == nil || !cl.AllowAccountDelete {
		WriteBearerError(w, withScheme(r, Error{Code: "insufficient_scope", Description: "this client may not delete accounts", Status: http.StatusForbidden}), nil)
		return
	}
	maxAge := realm.Tokens.AccountDeleteMaxAuthAge.Std()
	if claims.AuthTime.IsZero() || a.clock.Now().Sub(claims.AuthTime) > maxAge {
		WriteBearerError(w, withScheme(r, Error{Code: "insufficient_user_authentication", Description: "a more recent login is required", Status: http.StatusUnauthorized}),
			map[string]string{"max_age": strconv.FormatInt(int64(maxAge/time.Second), 10)})
		return
	}
	if usr == nil {
		usr, berr = a.bearer.User(r, realm, claims)
		if berr != nil {
			a.fail(w, r, withScheme(r, *berr))
			return
		}
	}
	// The deletion is by the user, not by an administrator or a provider:
	// the audit actor is "system" (design: User administration and import).
	err := a.users.Delete(r.Context(), "system", realm.Name, usr.ID, user.DeleteOptions{RevokeAtProvider: true})
	switch {
	case err == nil:
		noStore(w.Header())
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, user.ErrNotFound), errors.Is(err, store.ErrNotFound):
		a.fail(w, r, withScheme(r, *invalidToken())) // deleted since the lookup
	case errors.Is(err, store.ErrUnavailable):
		a.fail(w, r, Error{Code: "temporarily_unavailable", Description: "the service is temporarily unavailable", Status: http.StatusServiceUnavailable})
	default:
		a.log.ErrorContext(r.Context(), "account deletion failed", "error", err)
		a.fail(w, r, Error{Code: "server_error", Description: "the request could not be completed", Status: http.StatusInternalServerError})
	}
}

// fail answers a bearer error: with WWW-Authenticate for a 401, a plain JSON
// error for a store fault.
func (a *Account) fail(w http.ResponseWriter, r *http.Request, e Error) {
	switch e.Status {
	case http.StatusServiceUnavailable:
		a.log.WarnContext(r.Context(), "account deletion: the store is unavailable")
		WriteJSONError(w, e)
	case http.StatusInternalServerError:
		WriteJSONError(w, e)
	default:
		WriteBearerError(w, e, nil)
	}
}

// authenticateDPoP looks up the user of a DPoP request and remembers its proof's
// jti, in that order, answering the failure of either and returning it as nil.
func (a *Account) authenticateDPoP(w http.ResponseWriter, r *http.Request, realm *config.Realm, claims token.AccessClaims, proof *token.DPoPProof) (*store.User, *Error) {
	usr, berr := a.bearer.User(r, realm, claims)
	if berr == nil {
		berr = a.bearer.Remember(r.Context(), proof)
	}
	if berr != nil {
		e := withScheme(r, *berr)
		a.fail(w, r, e)
		return nil, &e
	}
	return usr, nil
}
