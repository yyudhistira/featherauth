package admin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
)

// Audit actions of the key commands.
const (
	ActionSealedListed  = "keys.sealed_listed"
	ActionTokenResealed = "identity.token_resealed"
	ActionTokenCleared  = "identity.token_cleared"
)

// Errors of the key operations, to be tested with errors.Is. Reseal returns
// them as a *KeyError, whose text names the key.
var (
	// ErrKeyNotConfigured means the key is not among the configured encryption keys.
	ErrKeyNotConfigured = errors.New("admin: key is not configured")
	// ErrKeyIsFirst means the key is the first one, which seals, so there is
	// no other key to reseal under.
	ErrKeyIsFirst = errors.New("admin: key is the first key")
)

// KeyError says why Reseal cannot use a key.
type KeyError struct {
	ID    string
	First bool // the key is the first key; otherwise it is not configured
}

func (e *KeyError) Error() string {
	if e.First {
		return fmt.Sprintf("key %s is the first key; add a new first key before resealing", e.ID)
	}
	return fmt.Sprintf("key %s is not in secrets.encryption_key_files", e.ID)
}

// Is makes the error match ErrKeyIsFirst or ErrKeyNotConfigured.
func (e *KeyError) Is(target error) bool {
	if e.First {
		return target == ErrKeyIsFirst
	}
	return target == ErrKeyNotConfigured
}

// SealedRef names an identity whose stored token a key sealed. It carries no
// part of the stored value.
type SealedRef struct {
	UserID   store.UserID
	Provider config.ProviderKey
	Subject  string
}

// LogValue implements slog.LogValuer: the user and the provider only.
func (r SealedRef) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user_id", string(r.UserID)), slog.String("provider", string(r.Provider)))
}

var _ slog.LogValuer = SealedRef{}

// ResealReport is the outcome of Reseal. Failed lists the identities whose
// value did not decrypt.
type ResealReport struct {
	Resealed int
	Skipped  int
	Failed   []SealedRef
}

// LogValue implements slog.LogValuer: the counts and the number of failures.
func (r ResealReport) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("resealed", r.Resealed), slog.Int("skipped", r.Skipped), slog.Int("failed", len(r.Failed)))
}

var _ slog.LogValuer = ResealReport{}

// ClearReport is the outcome of ClearSealed.
type ClearReport struct {
	Cleared int
	Skipped int
}

func checkKeyID(id string) error {
	if !secure.ValidKeyID(id) {
		return fmt.Errorf("%w: the key id must be 8 lowercase hex characters", ErrInvalid)
	}
	return nil
}

func refs(list []store.SealedIdentity) []SealedRef {
	out := make([]SealedRef, len(list))
	for i, s := range list {
		out[i] = SealedRef{UserID: s.UserID, Provider: s.Provider, Subject: s.Subject}
	}
	return out
}

// SealedBy lists the identities of the realm whose stored token the key sealed
// (the value starts with the key id and a dot), ordered by user id, provider
// and subject. It reads no key, so the key need not be configured. It writes
// one keys.sealed_listed row, also when the list is empty, and none when it
// fails.
func (o *Ops) SealedBy(ctx context.Context, realm config.RealmName, keyID string) ([]SealedRef, error) {
	if err := checkKeyID(keyID); err != nil {
		return nil, err
	}
	var out []SealedRef
	err := o.write(ctx, func(tx store.Tx) ([]func(), error) {
		rid, err := find(ctx, tx, realm)
		if err != nil {
			return nil, err
		}
		list, err := tx.Identities().SealedBy(ctx, rid, keyID)
		if err != nil {
			return nil, err
		}
		out = refs(list)
		p, err := o.audit.WriteTx(ctx, tx, audit.Event{
			Realm: rid, Actor: Actor, Action: ActionSealedListed,
			Details: map[string]any{"key_id": keyID, "identities": len(out)},
		})
		if err != nil {
			return nil, err
		}
		return []func(){p}, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// sealed returns the identities of the realm the key sealed, with the values,
// and writes no audit row.
func (o *Ops) sealed(ctx context.Context, realm config.RealmName, keyID string) ([]store.SealedIdentity, error) {
	var out []store.SealedIdentity
	err := o.store.Read(ctx, func(tx store.Tx) error {
		rid, err := find(ctx, tx, realm)
		if err != nil {
			return err
		}
		out, err = tx.Identities().SealedBy(ctx, rid, keyID)
		return err
	})
	return out, err
}

// Reseal decrypts the token of each identity SealedBy lists with the key keyID
// and seals it again under the first key of box, one write transaction and one
// identity.token_resealed row for each identity. The key must be in box and
// must not be its first key (a *KeyError says which), or nothing changes. A
// value that does not decrypt stays as it is and is counted as failed, with no
// row. A value is replaced only if it is still the one read: a token the
// service replaced or dropped meanwhile is counted as skipped. A store failure
// stops the run with the identity in progress unchanged; the ones done stay
// done.
func (o *Ops) Reseal(ctx context.Context, realm config.RealmName, keyID string, box *secure.Box) (ResealReport, error) {
	var rep ResealReport
	if err := checkKeyID(keyID); err != nil {
		return rep, err
	}
	if box == nil || !box.HasKey(keyID) {
		return rep, &KeyError{ID: keyID}
	}
	if box.FirstKeyID() == keyID {
		return rep, &KeyError{ID: keyID, First: true}
	}
	list, err := o.sealed(ctx, realm, keyID)
	if err != nil {
		return rep, err
	}
	to := box.FirstKeyID()
	for _, s := range list {
		plain, err := box.Open(s.Value)
		if err != nil {
			rep.Failed = append(rep.Failed, SealedRef{UserID: s.UserID, Provider: s.Provider, Subject: s.Subject})
			continue
		}
		next, err := box.Seal(plain)
		clear(plain)
		if err != nil {
			return rep, err
		}
		replaced, err := o.replaceToken(ctx, s, next, ActionTokenResealed,
			map[string]any{"provider": string(s.Provider), "from_key": keyID, "to_key": to})
		if err != nil {
			return rep, err
		}
		if replaced {
			rep.Resealed++
		} else {
			rep.Skipped++
		}
	}
	return rep, nil
}

// ClearSealed sets the stored token of each identity SealedBy lists to none, one
// write transaction and one identity.token_cleared row for each. It reads no key
// and revokes nothing at the provider. A value is replaced only if it is still
// the one read; otherwise it is counted as skipped.
func (o *Ops) ClearSealed(ctx context.Context, realm config.RealmName, keyID string) (ClearReport, error) {
	var rep ClearReport
	if err := checkKeyID(keyID); err != nil {
		return rep, err
	}
	list, err := o.sealed(ctx, realm, keyID)
	if err != nil {
		return rep, err
	}
	for _, s := range list {
		cleared, err := o.replaceToken(ctx, s, "", ActionTokenCleared,
			map[string]any{"provider": string(s.Provider), "key_id": keyID})
		if err != nil {
			return rep, err
		}
		if cleared {
			rep.Cleared++
		} else {
			rep.Skipped++
		}
	}
	return rep, nil
}

// replaceToken sets the token of s to next if it is still s.Value, with its
// audit row in the same transaction, and reports whether it did. The store runs
// the function again after a deadlock, so it keeps no state between runs.
func (o *Ops) replaceToken(ctx context.Context, s store.SealedIdentity, next, action string, details map[string]any) (bool, error) {
	replaced := false
	err := o.write(ctx, func(tx store.Tx) ([]func(), error) {
		replaced = false
		ok, err := tx.Identities().ReplaceProviderToken(ctx, s.RealmID, s.ID, s.Value, next)
		if err != nil || !ok {
			return nil, err
		}
		p, err := o.audit.WriteTx(ctx, tx, audit.Event{Realm: s.RealmID, Actor: Actor, Action: action, User: s.UserID, Details: details})
		if err != nil {
			return nil, err
		}
		replaced = true
		return []func(){p}, nil
	})
	return replaced, err
}
