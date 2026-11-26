package user

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
)

// Errors of the administration operations.
var (
	// ErrNotFound means the realm, the user or the identity does not exist.
	ErrNotFound = errors.New("user: not found")
	// ErrConflict means the identity is already linked to a user.
	ErrConflict = errors.New("user: identity already linked")
)

// Audit actions the Manager writes.
const (
	ActionDelete  = "user.delete"
	ActionDisable = "user.disable"
	ActionEnable  = "user.enable"
	ActionLink    = "identity.link"
	ActionUnlink  = "identity.unlink"
)

// RevokerFor returns the Revoker of a provider of a realm, or nil when that
// provider cannot revoke a stored token.
type RevokerFor func(realm, provider string) provider.Revoker

// RealmOf returns the configuration of the realm called name. It returns false
// when the configuration is not available: the revocation then queues no logout
// notification and logs one warning. It returns (nil, true) when the loaded
// configuration does not name the realm, so none of its clients takes logouts.
type RealmOf func(name config.RealmName) (*config.Realm, bool)

// DeleteOptions says how a user is deleted.
type DeleteOptions struct {
	// RevokeAtProvider revokes the stored provider refresh tokens at their
	// providers (account deletion by the user or an administrator). Off for
	// the deletion that a provider's own account-delete event asks for.
	RevokeAtProvider bool
}

// Manager deletes, disables, enables and links users. Every change is audited
// in the transaction that makes it; the audit line is logged after the commit.
// The actor of each audit row is the first argument: "admin", "system" or
// "provider:<name>".
type Manager struct {
	store    store.Store
	audit    Auditor
	box      *secure.Box
	revokers RevokerFor
	realmOf  RealmOf
	log      *slog.Logger
	clock    clock.Clock
	src      secure.Source
}

// NewManager returns a Manager. box opens the stored provider tokens and may
// be nil when the configuration has no encryption key; revokers may be nil.
// realmOf gives the configuration of a realm to queue back-channel logouts.
func NewManager(st store.Store, a Auditor, box *secure.Box, revokers RevokerFor, log *slog.Logger, c clock.Clock, src secure.Source, realmOf RealmOf) *Manager {
	return &Manager{store: st, audit: a, box: box, revokers: revokers, realmOf: realmOf, log: log, clock: c, src: src}
}

// realmNamed returns the configuration of the realm called name for
// store.QueueLogouts. When the configuration is not available it returns nil,
// which queues no logout, and logs one warning: the revocation itself goes on
// (the plain behaviour of the revoking commands).
func (m *Manager) realmNamed(ctx context.Context, name config.RealmName) *config.Realm {
	warn := func() {
		m.log.LogAttrs(ctx, slog.LevelWarn, "back-channel logout not queued: the realm's configuration is not available",
			slog.String("realm", string(name)))
	}
	if m.realmOf == nil {
		warn()
		return nil
	}
	r, ok := m.realmOf(name)
	switch {
	case !ok:
		warn()
		return nil
	case r == nil:
		return &config.Realm{Name: name}
	}
	return r
}

// change runs fn in one write transaction on the realm. When fn returns an
// event it is audited in that transaction. The returned functions run after
// the commit.
func (m *Manager) change(ctx context.Context, realm config.RealmName, actor string,
	fn func(tx store.Tx, rid store.RealmID) (*audit.Event, []func(), error)) error {
	return m.changeAll(ctx, realm, actor, func(tx store.Tx, rid store.RealmID) ([]*audit.Event, []func(), error) {
		ev, post, err := fn(tx, rid)
		if ev == nil {
			return nil, post, err
		}
		return []*audit.Event{ev}, post, err
	})
}

// changeAll is change for a change that writes several audit rows, in the order
// returned; each row is written in the same transaction.
func (m *Manager) changeAll(ctx context.Context, realm config.RealmName, actor string,
	fn func(tx store.Tx, rid store.RealmID) ([]*audit.Event, []func(), error)) error {
	var after []func()
	err := m.store.Write(ctx, func(tx store.Tx) error {
		after = nil
		rid, err := tx.Realms().Find(ctx, realm)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		evs, post, err := fn(tx, rid)
		if err != nil {
			return err
		}
		after = post
		var publishes []func()
		for _, ev := range evs {
			ev.Realm, ev.Actor = rid, actor
			publish, err := m.audit.WriteTx(ctx, tx, *ev)
			if err != nil {
				return err
			}
			publishes = append(publishes, publish)
		}
		after = append(publishes, after...)
		return nil
	})
	if err != nil {
		return err
	}
	for _, f := range after {
		f()
	}
	return nil
}

func getUser(ctx context.Context, tx store.Tx, rid store.RealmID, id store.UserID) (store.User, error) {
	u, err := tx.Users().Get(ctx, rid, id)
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, ErrNotFound
	}
	return u, err
}

// Delete removes the user, its identities and its refresh tokens. With
// RevokeAtProvider, the stored provider tokens are opened with the box and
// revoked at their providers after the commit; a token that cannot be opened,
// a provider without a revoker and a failing revoke are logged as warnings and
// never stop the deletion (SEC-10).
func (m *Manager) Delete(ctx context.Context, actor string, realm config.RealmName, id store.UserID, opts DeleteOptions) error {
	rc := m.realmNamed(ctx, realm)
	return m.change(ctx, realm, actor, func(tx store.Tx, rid store.RealmID) (*audit.Event, []func(), error) {
		if _, err := getUser(ctx, tx, rid, id); err != nil {
			return nil, nil, err
		}
		var post []func()
		if opts.RevokeAtProvider {
			ids, err := tx.Identities().ListByUser(ctx, rid, id)
			if err != nil {
				return nil, nil, err
			}
			for _, ident := range ids {
				if ident.ProviderRefreshTokenEnc != "" {
					post = append(post, m.revoke(ctx, realm, id, ident))
				}
			}
		}
		if err := tx.Users().Delete(ctx, rid, id); err != nil {
			return nil, nil, err
		}
		ended, err := tx.RefreshTokens().DeleteUser(ctx, rid, id)
		if err != nil {
			return nil, nil, err
		}
		if err := store.QueueLogouts(ctx, tx, rc, rid, ended.Sessions, m.clock, m.src); err != nil {
			return nil, nil, err
		}
		if err := tx.SSOSessions().DeleteByUser(ctx, rid, id); err != nil {
			return nil, nil, err
		}
		return &audit.Event{
			Action: ActionDelete, User: id,
			Details: map[string]any{"revoke_at_provider": opts.RevokeAtProvider},
		}, post, nil
	})
}

// revoke opens the stored token of an identity now (the row is deleted with
// the user) and returns the function that revokes it at the provider.
func (m *Manager) revoke(ctx context.Context, realm config.RealmName, uid store.UserID, ident store.Identity) func() {
	provKey := string(ident.Provider)
	warn := func(msg string, err error) func() {
		return func() {
			attrs := []slog.Attr{slog.String("user_id", string(uid)), slog.String("provider", provKey)}
			if err != nil {
				attrs = append(attrs, slog.Any("error", err))
			}
			m.log.LogAttrs(ctx, slog.LevelWarn, msg, attrs...)
		}
	}
	if m.box == nil {
		return warn("stored provider token could not be decrypted (no encryption key), provider revoke skipped", nil)
	}
	plain, err := m.box.Open(ident.ProviderRefreshTokenEnc)
	if err != nil {
		return warn("stored provider token could not be decrypted, provider revoke skipped", err)
	}
	token := string(plain)
	return func() {
		var rv provider.Revoker
		if m.revokers != nil {
			rv = m.revokers(string(realm), provKey)
		}
		if rv == nil {
			warn("provider has no revoker, provider revoke skipped", nil)()
			return
		}
		if err := rv.Revoke(ctx, token); err != nil {
			warn("provider revoke failed", err)()
		}
	}
}

// ChangeDisabled disables (disable true) or enables the user u inside tx. A
// user already in that state is left alone and the action is empty. Disabling
// revokes all the user's refresh tokens; enabling does not bring them back.
// It returns the audit action to write, ActionDisable or ActionEnable, and
// writes no audit row itself, so that every caller records it in its own
// transaction. Manager and the administration operations share it.
func (m *Manager) ChangeDisabled(ctx context.Context, tx store.Tx, realm config.RealmName, u store.User, disable bool) (string, error) {
	if disable == !u.DisabledAt.IsZero() {
		return "", nil
	}
	now := m.clock.Now()
	u.UpdatedAt = now
	action := ActionEnable
	if disable {
		u.DisabledAt, action = now, ActionDisable
	} else {
		u.DisabledAt = time.Time{}
	}
	if err := tx.Users().Update(ctx, u); err != nil {
		return "", err
	}
	if disable {
		ended, err := tx.RefreshTokens().RevokeUser(ctx, u.RealmID, u.ID, now)
		if err != nil {
			return "", err
		}
		if err := store.QueueLogouts(ctx, tx, m.realmNamed(ctx, realm), u.RealmID, ended.Sessions, m.clock, m.src); err != nil {
			return "", err
		}
		if err := tx.SSOSessions().DeleteByUser(ctx, u.RealmID, u.ID); err != nil {
			return "", err
		}
	}
	return action, nil
}

func (m *Manager) setDisabled(ctx context.Context, actor string, realm config.RealmName, id store.UserID, disable bool) error {
	return m.change(ctx, realm, actor, func(tx store.Tx, rid store.RealmID) (*audit.Event, []func(), error) {
		u, err := getUser(ctx, tx, rid, id)
		if err != nil {
			return nil, nil, err
		}
		action, err := m.ChangeDisabled(ctx, tx, realm, u, disable)
		if err != nil || action == "" {
			return nil, nil, err
		}
		return &audit.Event{Action: action, User: id}, nil, nil
	})
}

// ActionSessionsRevoked is the audit action of ending every live session of a
// user at once.
const ActionSessionsRevoked = "user.sessions_revoked"

// RevokeSessions ends every live session of the user, of every client, in one
// transaction, and returns how many it ended (a session is live while it has a
// refresh token that is neither revoked nor expired). When at least one ended,
// one user.sessions_revoked row with the count is written for the actor in the
// same transaction; when none did, nothing is changed and nothing is audited.
// An unknown realm or user gives ErrNotFound.
func (m *Manager) RevokeSessions(ctx context.Context, actor string, realm config.RealmName, id store.UserID) (int, error) {
	n := 0
	rc := m.realmNamed(ctx, realm)
	err := m.change(ctx, realm, actor, func(tx store.Tx, rid store.RealmID) (*audit.Event, []func(), error) {
		n = 0 // a run can repeat
		if _, err := getUser(ctx, tx, rid, id); err != nil {
			return nil, nil, err
		}
		now := m.clock.Now()
		live, err := tx.RefreshTokens().UserLiveSessions(ctx, rid, id, now)
		if err != nil {
			return nil, nil, err
		}
		var ended []store.EndedSession
		for _, s := range live {
			e, err := tx.RefreshTokens().RevokeSession(ctx, rid, s.SessionID, now)
			if err != nil {
				return nil, nil, err
			}
			ended = append(ended, e.Sessions...)
		}
		if err := store.QueueLogouts(ctx, tx, rc, rid, ended, m.clock, m.src); err != nil {
			return nil, nil, err
		}
		// Sign out everywhere ends the browser sessions too, whether or not a token
		// session was live (FR-45).
		if err := tx.SSOSessions().DeleteByUser(ctx, rid, id); err != nil {
			return nil, nil, err
		}
		n = len(live)
		if n == 0 {
			return nil, nil, nil
		}
		return &audit.Event{Action: ActionSessionsRevoked, User: id, Details: map[string]any{"sessions": n}}, nil, nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ErrSessionNotFound means the session is not a session of the user. It wraps
// ErrNotFound, so either check matches it.
var ErrSessionNotFound = fmt.Errorf("user: session not found: %w", ErrNotFound)

// RevokeSession ends one session of the user, of any client, when it is live
// (has a refresh token that is neither revoked nor expired), and returns 1. A
// session that is not live any more is left alone: it returns 0 and nothing is
// audited. When the session ended, one user.sessions_revoked row with the count
// 1 is written for the actor in the same transaction. A session that is not the
// user's gives ErrSessionNotFound; an unknown realm or user gives ErrNotFound.
func (m *Manager) RevokeSession(ctx context.Context, actor string, realm config.RealmName, id store.UserID, session store.SessionID) (int, error) {
	n := 0
	rc := m.realmNamed(ctx, realm)
	err := m.change(ctx, realm, actor, func(tx store.Tx, rid store.RealmID) (*audit.Event, []func(), error) {
		n = 0 // a run can repeat
		if _, err := getUser(ctx, tx, rid, id); err != nil {
			return nil, nil, err
		}
		now := m.clock.Now()
		live, err := tx.RefreshTokens().UserLiveSessions(ctx, rid, id, now)
		if err != nil {
			return nil, nil, err
		}
		target := false
		for _, s := range live {
			target = target || s.SessionID == session
		}
		if !target {
			owned, err := tx.RefreshTokens().HasSession(ctx, rid, id, session)
			if err != nil {
				return nil, nil, err
			}
			if !owned {
				return nil, nil, ErrSessionNotFound
			}
			return nil, nil, nil
		}
		ended, err := tx.RefreshTokens().RevokeSession(ctx, rid, session, now)
		if err != nil {
			return nil, nil, err
		}
		if err := store.QueueLogouts(ctx, tx, rc, rid, ended.Sessions, m.clock, m.src); err != nil {
			return nil, nil, err
		}
		n = 1
		return &audit.Event{Action: ActionSessionsRevoked, User: id, Details: map[string]any{"sessions": n}}, nil, nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Disable disables the user and revokes all its refresh tokens. A user that is
// disabled already is left alone and nothing is audited.
func (m *Manager) Disable(ctx context.Context, actor string, realm config.RealmName, id store.UserID) error {
	return m.setDisabled(ctx, actor, realm, id, true)
}

// Enable enables the user. Sessions revoked by Disable stay revoked. A user
// that is enabled already is left alone and nothing is audited.
func (m *Manager) Enable(ctx context.Context, actor string, realm config.RealmName, id store.UserID) error {
	return m.setDisabled(ctx, actor, realm, id, false)
}

// Link attaches a provider identity to the user. An identity that is linked
// already, to this or another user, gives ErrConflict.
func (m *Manager) Link(ctx context.Context, actor string, realm config.RealmName, id store.UserID, prov config.ProviderKey, subject string) error {
	return m.change(ctx, realm, actor, func(tx store.Tx, rid store.RealmID) (*audit.Event, []func(), error) {
		if _, err := getUser(ctx, tx, rid, id); err != nil {
			return nil, nil, err
		}
		iid, err := secure.NewID(m.src, m.clock)
		if err != nil {
			return nil, nil, err
		}
		err = tx.Identities().Create(ctx, store.Identity{
			ID: store.IdentityID(iid), RealmID: rid, UserID: id, Provider: prov,
			ProviderSub: subject, CreatedAt: m.clock.Now(),
		})
		if errors.Is(err, store.ErrConflict) {
			return nil, nil, ErrConflict
		}
		if err != nil {
			return nil, nil, fmt.Errorf("user: link identity: %w", err)
		}
		return &audit.Event{Action: ActionLink, User: id, Details: map[string]any{"provider": string(prov)}}, nil, nil
	})
}

// Unlink removes a provider identity from the user. An identity that does not
// exist or belongs to another user gives ErrNotFound.
func (m *Manager) Unlink(ctx context.Context, actor string, realm config.RealmName, id store.UserID, prov config.ProviderKey, subject string) error {
	return m.change(ctx, realm, actor, func(tx store.Tx, rid store.RealmID) (*audit.Event, []func(), error) {
		if _, err := getUser(ctx, tx, rid, id); err != nil {
			return nil, nil, err
		}
		ident, err := tx.Identities().Find(ctx, rid, prov, subject)
		if errors.Is(err, store.ErrNotFound) || (err == nil && ident.UserID != id) {
			return nil, nil, ErrNotFound
		}
		if err != nil {
			return nil, nil, err
		}
		if err := tx.Identities().Delete(ctx, rid, ident.ID); err != nil {
			return nil, nil, err
		}
		if err := tx.SSOSessions().DeleteByIdentity(ctx, rid, ident.ID); err != nil {
			return nil, nil, err
		}
		return &audit.Event{Action: ActionUnlink, User: id, Details: map[string]any{"provider": string(prov)}}, nil, nil
	})
}

// ActionRealmSessionsRevoked is the audit action of ending every live session of
// a realm at once.
const ActionRealmSessionsRevoked = "realm.sessions_revoked"

// RevokeRealmSessions ends every live session of the realm, of every user, and
// returns how many it ended. When at least one ended, one realm.sessions_revoked
// row (no user) with the count is written for the actor in the same transaction,
// with the back-channel logouts of the sessions. An unknown realm gives
// ErrNotFound.
func (m *Manager) RevokeRealmSessions(ctx context.Context, actor string, realm config.RealmName) (int, error) {
	n := 0
	rc := m.realmNamed(ctx, realm)
	err := m.change(ctx, realm, actor, func(tx store.Tx, rid store.RealmID) (*audit.Event, []func(), error) {
		n = 0 // a run can repeat
		now := m.clock.Now()
		live, err := tx.RefreshTokens().RealmLiveSessions(ctx, rid, now)
		if err != nil {
			return nil, nil, err
		}
		var ended []store.EndedSession
		for _, s := range live {
			e, err := tx.RefreshTokens().RevokeSession(ctx, rid, s.SessionID, now)
			if err != nil {
				return nil, nil, err
			}
			ended = append(ended, e.Sessions...)
		}
		if err := store.QueueLogouts(ctx, tx, rc, rid, ended, m.clock, m.src); err != nil {
			return nil, nil, err
		}
		// Every user's sessions end, so every browser session of the realm ends (FR-45).
		if err := tx.SSOSessions().DeleteByRealm(ctx, rid); err != nil {
			return nil, nil, err
		}
		n = len(live)
		if n == 0 {
			return nil, nil, nil
		}
		return &audit.Event{Action: ActionRealmSessionsRevoked, Details: map[string]any{"sessions": n}}, nil, nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
