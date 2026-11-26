package user

import (
	"context"
	"errors"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
)

// ActionConsentRevoked is the audit action of a provider's consent-revoked
// event.
const ActionConsentRevoked = "identity.consent_revoked"

// ActionIdentitySessionsRevoked is the audit action of a Google security event
// that ended at least one session (Google Cross-Account Protection).
const ActionIdentitySessionsRevoked = "identity.sessions_revoked"

// providerActor is the audit actor of a change a provider's event asked for.
func providerActor(prov config.ProviderKey) string { return "provider:" + string(prov) }

// identityOf finds the identity a provider event is about; a subject that is
// not stored gives ErrNotFound.
func identityOf(ctx context.Context, tx store.Tx, rid store.RealmID, prov config.ProviderKey, sub string) (store.Identity, error) {
	ident, err := tx.Identities().Find(ctx, rid, prov, sub)
	if errors.Is(err, store.ErrNotFound) {
		return store.Identity{}, ErrNotFound
	}
	return ident, err
}

// ConsentRevoked acts on a provider's consent-revoked event: it revokes every
// session of the user who holds the identity and drops the stored provider
// token. The user, the identity and the user's sub stay. An unknown identity
// gives ErrNotFound. The actor of the audit row is provider:<key>.
func (m *Manager) ConsentRevoked(ctx context.Context, realm config.RealmName, prov config.ProviderKey, sub string) error {
	rc := m.realmNamed(ctx, realm)
	return m.change(ctx, realm, providerActor(prov), func(tx store.Tx, rid store.RealmID) (*audit.Event, []func(), error) {
		ev, err := m.consentRevoked(ctx, tx, rid, rc, prov, sub)
		return ev, nil, err
	})
}

// consentRevoked makes the change of ConsentRevoked inside its transaction and
// returns the audit row of the change.
func (m *Manager) consentRevoked(ctx context.Context, tx store.Tx, rid store.RealmID, rc *config.Realm, prov config.ProviderKey, sub string) (*audit.Event, error) {
	ident, err := identityOf(ctx, tx, rid, prov, sub)
	if err != nil {
		return nil, err
	}
	if err := tx.Identities().SetProviderToken(ctx, rid, ident.ID, ""); err != nil {
		return nil, err
	}
	ended, err := tx.RefreshTokens().RevokeUser(ctx, rid, ident.UserID, m.clock.Now())
	if err != nil {
		return nil, err
	}
	if err := store.QueueLogouts(ctx, tx, rc, rid, ended.Sessions, m.clock, m.src); err != nil {
		return nil, err
	}
	if err := endBrowserSessions(ctx, tx, rid, ident); err != nil {
		return nil, err
	}
	return &audit.Event{Action: ActionConsentRevoked, User: ident.UserID, Details: map[string]any{"provider": string(prov)}}, nil
}

// AccountDeleted acts on a provider's account-delete event. When the identity
// is the user's only one, the user is deleted with its refresh tokens and
// nothing is revoked at the provider; otherwise the identity is unlinked and
// the user's sessions are revoked. An unknown identity gives ErrNotFound. The
// actor of the audit row is provider:<key>.
func (m *Manager) AccountDeleted(ctx context.Context, realm config.RealmName, prov config.ProviderKey, sub string) error {
	rc := m.realmNamed(ctx, realm)
	return m.change(ctx, realm, providerActor(prov), func(tx store.Tx, rid store.RealmID) (*audit.Event, []func(), error) {
		ev, err := m.accountDeleted(ctx, tx, rid, rc, prov, sub)
		return ev, nil, err
	})
}

// accountDeleted makes the change of AccountDeleted inside its transaction and
// returns the audit row of the change.
func (m *Manager) accountDeleted(ctx context.Context, tx store.Tx, rid store.RealmID, rc *config.Realm, prov config.ProviderKey, sub string) (*audit.Event, error) {
	ident, err := identityOf(ctx, tx, rid, prov, sub)
	if err != nil {
		return nil, err
	}
	all, err := tx.Identities().ListByUser(ctx, rid, ident.UserID)
	if err != nil {
		return nil, err
	}
	if len(all) <= 1 {
		if err := tx.Users().Delete(ctx, rid, ident.UserID); err != nil {
			return nil, err
		}
		ended, err := tx.RefreshTokens().DeleteUser(ctx, rid, ident.UserID)
		if err != nil {
			return nil, err
		}
		if err := store.QueueLogouts(ctx, tx, rc, rid, ended.Sessions, m.clock, m.src); err != nil {
			return nil, err
		}
		if err := tx.SSOSessions().DeleteByUser(ctx, rid, ident.UserID); err != nil {
			return nil, err
		}
		return &audit.Event{Action: ActionDelete, User: ident.UserID, Details: map[string]any{"revoke_at_provider": false}}, nil
	}
	if err := tx.Identities().Delete(ctx, rid, ident.ID); err != nil {
		return nil, err
	}
	ended, err := tx.RefreshTokens().RevokeUser(ctx, rid, ident.UserID, m.clock.Now())
	if err != nil {
		return nil, err
	}
	if err := store.QueueLogouts(ctx, tx, rc, rid, ended.Sessions, m.clock, m.src); err != nil {
		return nil, err
	}
	if err := endBrowserSessions(ctx, tx, rid, ident); err != nil {
		return nil, err
	}
	return &audit.Event{Action: ActionUnlink, User: ident.UserID, Details: map[string]any{"provider": string(prov)}}, nil
}

// endBrowserSessions ends the browser sessions of a provider event that revoked
// the user's sessions (FR-45): the sessions made with the identity, and every
// browser session of the user, which the revoked token sessions imply.
func endBrowserSessions(ctx context.Context, tx store.Tx, rid store.RealmID, ident store.Identity) error {
	if err := tx.SSOSessions().DeleteByIdentity(ctx, rid, ident.ID); err != nil {
		return err
	}
	return tx.SSOSessions().DeleteByUser(ctx, rid, ident.UserID)
}

// EventResult says what ProviderEvent did with an event.
type EventResult int

const (
	// EventApplied means the event's change was made and audited.
	EventApplied EventResult = iota + 1
	// EventRepeated means the event was acted on before; nothing changed.
	EventRepeated
	// EventUnknownSubject means no identity has the event's subject; nothing
	// changed.
	EventUnknownSubject
	// EventUnknownType means the event's type has no action; nothing changed.
	EventUnknownType
	// EventLogOnly means the event is an email change, which is only logged.
	EventLogOnly
)

// ProviderEvents acts on the events of one provider token once (SEC-27). The
// events share one id and expiry, which are remembered in the same write
// transaction as the changes of the events, when the id is new; a repeated id
// changes nothing and gives EventRepeated for each event. A failed change
// remembers nothing, so the provider's retry is acted on. The results are in the
// order of the events, and an empty list does nothing. An unknown subject is a
// result, not an error.
//
// The types that act depend on the event's set (provider.EventSet): Apple's
// consent-revoked, account-delete and account-deleted (the name in Apple's
// documentation, with the same action) and its email changes, Meta's
// account-delete, and Google's sessions-revoked, tokens-revoked and
// account-disabled, which revoke the sessions of the identity's user. A type that
// the set does not list is unknown. The actor of the audit rows is provider:<key>.
func (m *Manager) ProviderEvents(ctx context.Context, realm config.RealmName, prov config.ProviderKey, evs []provider.Event) ([]EventResult, error) {
	if len(evs) == 0 {
		return nil, nil
	}
	rc := m.realmNamed(ctx, realm)
	res := make([]EventResult, len(evs))
	err := m.changeAll(ctx, realm, providerActor(prov), func(tx store.Tx, rid store.RealmID) ([]*audit.Event, []func(), error) {
		for i := range res {
			res[i] = EventRepeated
		}
		first, err := tx.ProviderEvents().Remember(ctx, rid, prov, secure.HashOf(evs[0].ID), evs[0].Expires)
		if err != nil || !first {
			return nil, nil, err
		}
		var audits []*audit.Event
		for i, ev := range evs {
			a, out, err := m.applyEvent(ctx, tx, rid, rc, prov, ev)
			if err != nil {
				return nil, nil, err
			}
			res[i] = out
			if a != nil {
				audits = append(audits, a)
			}
		}
		return audits, nil, nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// identityRevoked acts on a Google security event that revokes the sessions of
// the user who holds the identity: their refresh tokens are revoked, the logouts
// of their sessions are queued, and their browser sessions end (FR-45). The user
// and the identity stay. The audit row is written only when a session ended, and
// names the event. An unknown identity gives ErrNotFound.
func (m *Manager) identityRevoked(ctx context.Context, tx store.Tx, rid store.RealmID, rc *config.Realm, prov config.ProviderKey, ev provider.Event) (*audit.Event, error) {
	ident, err := identityOf(ctx, tx, rid, prov, ev.Subject)
	if err != nil {
		return nil, err
	}
	ended, err := tx.RefreshTokens().RevokeUser(ctx, rid, ident.UserID, m.clock.Now())
	if err != nil {
		return nil, err
	}
	if err := store.QueueLogouts(ctx, tx, rc, rid, ended.Sessions, m.clock, m.src); err != nil {
		return nil, err
	}
	if err := endBrowserSessions(ctx, tx, rid, ident); err != nil {
		return nil, err
	}
	if len(ended.Sessions) == 0 {
		return nil, nil
	}
	return &audit.Event{Action: ActionIdentitySessionsRevoked, User: ident.UserID, Details: map[string]any{"provider": string(prov), "event": ev.Type}}, nil
}

// applyEvent makes the change of a new event inside ProviderEvents'
// transaction and returns the audit row of the change, if there is one. The
// event's set decides which types act (see provider.EventSet): a type that the
// set does not list is unknown and changes nothing.
func (m *Manager) applyEvent(ctx context.Context, tx store.Tx, rid store.RealmID, rc *config.Realm, prov config.ProviderKey, ev provider.Event) (*audit.Event, EventResult, error) {
	switch ev.Set {
	case provider.EventSetApple:
		switch ev.Type {
		case "consent-revoked":
			return eventOutcome(m.consentRevoked(ctx, tx, rid, rc, prov, ev.Subject))
		case "account-delete", "account-deleted":
			return eventOutcome(m.accountDeleted(ctx, tx, rid, rc, prov, ev.Subject))
		case "email-disabled", "email-enabled":
			return nil, EventLogOnly, nil
		}
	case provider.EventSetMeta:
		if ev.Type == "account-delete" {
			return eventOutcome(m.accountDeleted(ctx, tx, rid, rc, prov, ev.Subject))
		}
	case provider.EventSetGoogle:
		switch ev.Type {
		case "sessions-revoked", "tokens-revoked", "account-disabled":
			if ev.Subject == "" {
				return nil, EventUnknownSubject, nil
			}
			return eventOutcome(m.identityRevoked(ctx, tx, rid, rc, prov, ev))
		case "token-revoked", "account-enabled", "account-credential-change-required", "verification":
			return nil, EventLogOnly, nil
		}
	}
	return nil, EventUnknownType, nil
}

// eventOutcome turns the result of an action into the audit row and the result
// of the event: an unknown identity is a result, not an error.
func eventOutcome(a *audit.Event, err error) (*audit.Event, EventResult, error) {
	switch {
	case err == nil:
		return a, EventApplied, nil
	case errors.Is(err, ErrNotFound):
		return nil, EventUnknownSubject, nil
	default:
		return nil, 0, err
	}
}
