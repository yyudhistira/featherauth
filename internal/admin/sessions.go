package admin

import (
	"context"
	"errors"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/user"
)

// Audit actions of the session operations.
const (
	ActionSessionsRevoked      = user.ActionSessionsRevoked
	ActionRealmSessionsRevoked = user.ActionRealmSessionsRevoked
)

// userExists returns ErrNotFound when the realm has no such user.
func userExists(ctx context.Context, tx store.Tx, rid store.RealmID, id store.UserID) error {
	_, err := tx.Users().Get(ctx, rid, id)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// ListSessions returns the active sessions of the user: the sessions with a
// refresh token that is neither revoked nor expired now, ordered by start time.
// It returns ErrNotFound when the realm or the user does not exist.
func (o *Ops) ListSessions(ctx context.Context, realm config.RealmName, id store.UserID) ([]store.LiveSession, error) {
	var out []store.LiveSession
	err := o.store.Read(ctx, func(tx store.Tx) error {
		rid, err := find(ctx, tx, realm)
		if err != nil {
			return err
		}
		if err := userExists(ctx, tx, rid, id); err != nil {
			return err
		}
		out, err = tx.RefreshTokens().UserLiveSessions(ctx, rid, id, o.clock.Now())
		return err
	})
	return out, err
}

// RevokeSessions ends the active sessions of the user and returns how many it
// ended. With an empty session every active session ends (user.Manager does
// it, as it does for the sign out everywhere of the bearer logout); with a
// session id only that one does (user.Manager.RevokeSession, which the bearer
// logout uses too). A session that is not active is left alone and nothing is
// audited. A session that does not belong to the user, and an unknown user or
// realm, give ErrNotFound. When at least one session ended, one
// user.sessions_revoked row is written for the actor, with the count.
func (o *Ops) RevokeSessions(ctx context.Context, actor string, realm config.RealmName, id store.UserID, session store.SessionID) (int, error) {
	if session == "" {
		return o.users.RevokeSessions(ctx, actor, realm, id)
	}
	return o.users.RevokeSession(ctx, actor, realm, id, session)
}

// RevokeRealmSessions ends every active session of the realm, of every user, and
// returns how many it ended (user.Manager does it, with its audit row and the
// back-channel logouts). An unknown realm gives ErrNotFound.
func (o *Ops) RevokeRealmSessions(ctx context.Context, actor string, realm config.RealmName) (int, error) {
	return o.users.RevokeRealmSessions(ctx, actor, realm)
}
