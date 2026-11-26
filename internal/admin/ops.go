// Package admin holds the user administration operations the featherauth CLI
// calls: get, list by email, update, disable, enable, delete, link, unlink,
// import and backup. They work on the store directly; there is no HTTP.
// Every change writes its audit row with the actor "admin" in the transaction
// that makes it and logs the audit line to the logger it was given.
package admin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
	"github.com/yyudhistira/featherauth/internal/user"
)

// Errors of the operations, to be tested with errors.Is.
var (
	// ErrNotFound means the realm, the user or the identity does not exist.
	ErrNotFound = user.ErrNotFound
	// ErrConflict means the change would give an email a second verified
	// holder, or link an identity that is linked already.
	ErrConflict = user.ErrConflict
	// ErrInvalid means the input is not acceptable; the error text says why.
	ErrInvalid = errors.New("admin: invalid input")
)

// Audit actions the operations write besides those of the user package.
const (
	ActionUpdate = "user.update"
	ActionImport = "user.import"
)

// Actor is the audit actor of every operation.
const Actor = "admin"

// Ops is the set of administration operations. It is safe for concurrent use.
type Ops struct {
	store store.Store
	users *user.Manager
	audit *audit.Writer
	clock clock.Clock
}

// NewOps returns Ops on the store. users carries out the deletion, disabling,
// enabling and linking, and writes their audit rows; it and Ops should log to
// the same logger l (made by logx.New).
func NewOps(st store.Store, users *user.Manager, c clock.Clock, l *slog.Logger) *Ops {
	return &Ops{store: st, users: users, audit: audit.NewWriter(st, l, c, secure.Default), clock: c}
}

// Record is a user with its identities. The stored provider tokens are left out.
type Record struct {
	User       store.User
	Identities []store.Identity
}

// LogValue implements slog.LogValuer. The user holds an email and a name, so
// only the ids are logged (SEC-13).
func (r Record) LogValue() slog.Value {
	ids := make([]string, len(r.Identities))
	for i, id := range r.Identities {
		ids[i] = string(id.ID)
	}
	return slog.GroupValue(
		slog.String("user_id", string(r.User.ID)),
		slog.String("realm_id", string(r.User.RealmID)),
		slog.Any("identity_ids", ids),
	)
}

var _ slog.LogValuer = Record{}

// Fields are the user fields a script may change; a nil field stays as it is.
// The id (sub) and the realm are not here because they cannot change.
// Disabled true disables the user and revokes its sessions, false enables it
// (revoked sessions stay revoked); it happens in the same transaction as the
// other changes, with its own audit row. Changing the email to a different
// address clears email_verified unless EmailVerified is given too.
type Fields struct {
	Name          *string
	Email         *string
	EmailVerified *bool
	Disabled      *bool
}

// LogValue implements slog.LogValuer. Fields hold an email and a name, so only
// the names of the fields that are set are logged (SEC-13).
func (f Fields) LogValue() slog.Value {
	var set []string
	if f.Name != nil {
		set = append(set, "name")
	}
	if f.Email != nil {
		set = append(set, "email")
	}
	if f.EmailVerified != nil {
		set = append(set, "email_verified")
	}
	if f.Disabled != nil {
		set = append(set, "disabled")
	}
	return slog.GroupValue(slog.Any("fields", set))
}

var _ slog.LogValuer = Fields{}

// find returns the id of the realm, or ErrNotFound.
func find(ctx context.Context, tx store.Tx, realm config.RealmName) (store.RealmID, error) {
	rid, err := tx.Realms().Find(ctx, realm)
	if errors.Is(err, store.ErrNotFound) {
		return "", ErrNotFound
	}
	return rid, err
}

// Get returns the user and its identities.
func (o *Ops) Get(ctx context.Context, realm config.RealmName, id store.UserID) (Record, error) {
	var rec Record
	err := o.store.Read(ctx, func(tx store.Tx) error {
		rid, err := find(ctx, tx, realm)
		if err != nil {
			return err
		}
		u, err := tx.Users().Get(ctx, rid, id)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		ids, err := tx.Identities().ListByUser(ctx, rid, id)
		if err != nil {
			return err
		}
		for i := range ids {
			ids[i].ProviderRefreshTokenEnc = ""
		}
		rec = Record{User: u, Identities: ids}
		return nil
	})
	return rec, err
}

// ListByEmail returns every user of the realm whose email equals the given one
// ignoring case and surrounding spaces, verified or not, oldest first.
func (o *Ops) ListByEmail(ctx context.Context, realm config.RealmName, email string) ([]store.User, error) {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" {
		return nil, fmt.Errorf("%w: email is empty", ErrInvalid)
	}
	var out []store.User
	err := o.store.Read(ctx, func(tx store.Tx) error {
		rid, err := find(ctx, tx, realm)
		if err != nil {
			return err
		}
		out, err = tx.Users().ListByEmailKey(ctx, rid, key)
		return err
	})
	return out, err
}

// UpdateResult says what an Update did beyond the fields it was given.
type UpdateResult struct {
	// VerificationCleared is true when the update changed the email to a
	// different address and so set email_verified to false.
	VerificationCleared bool
}

// Update changes the given fields, and disables or enables the user, in one
// transaction. A change that alters nothing writes nothing. The audit details
// of user.update list the names of the changed fields, never their values;
// disabling and enabling have their own rows, as the Disable and Enable
// operations write them.
func (o *Ops) Update(ctx context.Context, realm config.RealmName, id store.UserID, f Fields) (UpdateResult, error) {
	var res UpdateResult
	if f.Name == nil && f.Email == nil && f.EmailVerified == nil && f.Disabled == nil {
		return res, fmt.Errorf("%w: no field to change", ErrInvalid)
	}
	err := o.write(ctx, func(tx store.Tx) ([]func(), error) {
		// The store runs this again after a deadlock: a run starts with no result.
		res = UpdateResult{}
		rid, err := find(ctx, tx, realm)
		if err != nil {
			return nil, err
		}
		u, err := tx.Users().Get(ctx, rid, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		var changed []any
		cleared := false
		if f.Name != nil && *f.Name != u.Name {
			u.Name = *f.Name
			changed = append(changed, "name")
		}
		if f.Email != nil && strings.TrimSpace(*f.Email) != u.Email {
			oldKey := u.EmailKey
			u.Email = strings.TrimSpace(*f.Email)
			u.EmailKey = strings.ToLower(u.Email)
			changed = append(changed, "email")
			// A verification belongs to the address it was given for: a
			// different address is unverified unless the script says otherwise.
			if u.EmailKey != oldKey && f.EmailVerified == nil && u.EmailVerified {
				u.EmailVerified = false
				changed = append(changed, "email_verified")
				cleared = true
			}
		}
		if f.EmailVerified != nil && *f.EmailVerified != u.EmailVerified {
			u.EmailVerified = *f.EmailVerified
			changed = append(changed, "email_verified")
		}
		if u.EmailVerified && u.EmailKey == "" {
			return nil, fmt.Errorf("%w: a user without an email cannot have a verified email", ErrInvalid)
		}
		now := o.clock.Now()
		var publish []func()
		emit := func(action string, details map[string]any) error {
			p, err := o.audit.WriteTx(ctx, tx, audit.Event{Realm: rid, Actor: Actor, Action: action, User: id, Details: details})
			if err == nil {
				publish = append(publish, p)
			}
			return err
		}
		if len(changed) > 0 {
			u.UpdatedAt = now
			if err := tx.Users().Update(ctx, u); err != nil {
				if errors.Is(err, store.ErrConflict) {
					return nil, ErrConflict
				}
				return nil, err
			}
			if err := emit(ActionUpdate, map[string]any{"fields": changed}); err != nil {
				return nil, err
			}
		}
		if f.Disabled != nil {
			action, err := o.users.ChangeDisabled(ctx, tx, realm, u, *f.Disabled)
			if err != nil {
				return nil, err
			}
			if action != "" {
				if err := emit(action, nil); err != nil {
					return nil, err
				}
			}
		}
		res = UpdateResult{VerificationCleared: cleared}
		return publish, nil
	})
	if err != nil {
		return UpdateResult{}, err
	}
	return res, nil
}

// write runs fn in a write transaction and, once it has committed, calls the
// functions fn returned (they log the audit lines).
func (o *Ops) write(ctx context.Context, fn func(tx store.Tx) ([]func(), error)) error {
	var publish []func()
	err := o.store.Write(ctx, func(tx store.Tx) (err error) {
		publish, err = fn(tx)
		return err
	})
	if err != nil {
		return err
	}
	for _, p := range publish {
		p()
	}
	return nil
}

// Disable disables the user and revokes its sessions.
func (o *Ops) Disable(ctx context.Context, realm config.RealmName, id store.UserID) error {
	return o.users.Disable(ctx, Actor, realm, id)
}

// Enable enables the user; its revoked sessions stay revoked.
func (o *Ops) Enable(ctx context.Context, realm config.RealmName, id store.UserID) error {
	return o.users.Enable(ctx, Actor, realm, id)
}

// Delete removes the user, its identities and its sessions, and revokes the
// stored provider refresh tokens at their providers (SEC-10).
func (o *Ops) Delete(ctx context.Context, realm config.RealmName, id store.UserID) error {
	return o.users.Delete(ctx, Actor, realm, id, user.DeleteOptions{RevokeAtProvider: true})
}

// Link attaches the provider identity to the user; ErrConflict when it is
// linked already.
func (o *Ops) Link(ctx context.Context, realm config.RealmName, id store.UserID, prov config.ProviderKey, subject string) error {
	if strings.TrimSpace(string(prov)) == "" || subject == "" {
		return fmt.Errorf("%w: provider and subject are required", ErrInvalid)
	}
	return o.users.Link(ctx, Actor, realm, id, prov, subject)
}

// Unlink removes the provider identity from the user.
func (o *Ops) Unlink(ctx context.Context, realm config.RealmName, id store.UserID, prov config.ProviderKey, subject string) error {
	if strings.TrimSpace(string(prov)) == "" || subject == "" {
		return fmt.Errorf("%w: provider and subject are required", ErrInvalid)
	}
	return o.users.Unlink(ctx, Actor, realm, id, prov, subject)
}

// Backup writes a snapshot to dir named from the clock in server local time
// and keeps the newest keep snapshots there. It returns the path written. A
// snapshot changes no data, so it writes no audit row.
func (o *Ops) Backup(ctx context.Context, dir string, keep int) (string, error) {
	if keep < 1 {
		return "", fmt.Errorf("%w: snapshots to keep must be at least 1", ErrInvalid)
	}
	return store.Snapshot(ctx, o.store, dir, o.clock.Now().Local(), keep)
}
