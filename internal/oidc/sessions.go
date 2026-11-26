package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/server"
	"github.com/yyudhistira/featherauth/internal/store"
)

// SessionLister lists the live sessions of a user. admin.Ops has it; oidc
// cannot import admin (same rank), so the caller passes it in.
type SessionLister interface {
	ListSessions(ctx context.Context, realm config.RealmName, id store.UserID) ([]store.LiveSession, error)
}

// SessionsConfig is what the sessions endpoint needs.
type SessionsConfig struct {
	// Bearer authenticates the request; required.
	Bearer *BearerAuth
	// Lister lists the user's live sessions; required.
	Lister SessionLister
	// Log is the service logger (logx); required.
	Log *slog.Logger
}

// Sessions is the sessions endpoint of "Sessions of the signed-in user": the
// live sessions of the token's user, for a client with allow_session_management.
type Sessions struct {
	bearer *BearerAuth
	lister SessionLister
	log    *slog.Logger
}

// NewSessions returns the sessions endpoint.
func NewSessions(c SessionsConfig) *Sessions {
	return &Sessions{bearer: c.Bearer, lister: c.Lister, log: c.Log}
}

var _ http.Handler = (*Sessions)(nil)

// SessionFields is one session as the sessions endpoint and `featherauth
// session list` print it. Both use this type, so the fields and the time
// format cannot drift apart.
type SessionFields struct {
	SessionID  string    `json:"session_id"`
	ClientID   string    `json:"client_id"`
	StartedAt  time.Time `json:"started_at"`
	AuthTime   time.Time `json:"auth_time"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// SessionFieldsOf returns the fields of a live session, in UTC.
func SessionFieldsOf(s store.LiveSession) SessionFields {
	return SessionFields{
		SessionID: string(s.SessionID), ClientID: string(s.ClientID),
		StartedAt: s.StartedAt.UTC(), AuthTime: s.AuthTime.UTC(),
		LastUsedAt: s.LastUsedAt.UTC(), ExpiresAt: s.ExpiresAt.UTC(),
	}
}

// sessionView is one entry of the sessions list: the SessionFields and current.
type sessionView struct {
	SessionFields
	Current bool `json:"current"`
}

// ServeHTTP answers GET /{realm}/sessions with the bearer access token. A
// preflight is answered by the CORS middleware; the origin rule is that of
// /userinfo: it is checked against the token's azp client after the token check.
func (s *Sessions) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info, ok := server.FromContext(r.Context())
	if !ok || info.Realm == nil {
		serverError(w, r, info)
		return
	}
	if !server.AllowMethods(w, r, http.MethodGet, http.MethodOptions) {
		return
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	claims, usr, berr := s.bearer.Bearer(r, info.Realm, config.EndpointSessions)
	if berr != nil {
		writeBearerFailure(w, r, s.log, berr, "sessions")
		return
	}
	_ = server.AllowOrigin(w, r, info.Realm.Clients[config.ClientID(claims.Azp)])
	if !mayManageSessions(info.Realm, claims.Azp) {
		refuseSessionManagement(w, r)
		return
	}
	live, err := s.lister.ListSessions(r.Context(), info.Realm.Name, usr.ID)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrNotFound):
		WriteBearerError(w, withScheme(r, *invalidToken()), nil) // the user was removed since the token check
		return
	default:
		writeBearerFailure(w, r, s.log, storeError(err), "sessions")
		return
	}
	out := make([]sessionView, 0, len(live))
	for _, ss := range live {
		out = append(out, sessionView{
			SessionFields: SessionFieldsOf(ss),
			Current:       string(ss.SessionID) == string(claims.Sid),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// mayManageSessions reports whether the client azp of a token has
// allow_session_management. A client removed since the token was issued has
// not.
func mayManageSessions(realm *config.Realm, azp string) bool {
	cl := realm.Clients[config.ClientID(azp)]
	return cl != nil && cl.AllowSessionManagement
}

// refuseSessionManagement answers a client without allow_session_management:
// 403 insufficient_scope.
func refuseSessionManagement(w http.ResponseWriter, r *http.Request) {
	WriteBearerError(w, withScheme(r, Error{Code: "insufficient_scope", Description: "this client may not manage sessions", Status: http.StatusForbidden}), nil)
}
