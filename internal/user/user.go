// Package user resolves a provider identity to a user of a realm: it finds the
// user of a known identity, links a new identity to an existing user under the
// auto-link rules, or creates a new user (Email rules in the design).
package user

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/provider"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
	"github.com/yyudhistira/featherauth/internal/store/audit"
)

// Errors of Resolve; the caller maps both to access_denied.
var (
	// ErrDisabled means the user the login resolves to is disabled.
	ErrDisabled = errors.New("user: disabled")
	// ErrRefused means the login is refused outright: the realm is disabled
	// or the provider gave no subject.
	ErrRefused = errors.New("user: login refused")
)

// ActionAutoLink is the audit action written when an identity is linked to an
// existing user.
const ActionAutoLink = "identity.auto_link"

// Auditor stores an audit event in the caller's transaction and returns the
// function that logs it once that transaction has committed (audit.Writer).
type Auditor interface {
	WriteTx(ctx context.Context, tx store.Tx, e audit.Event) (func(), error)
}

var _ Auditor = (*audit.Writer)(nil)

// ResolveInput is a login to resolve: the realm, the provider (and its key)
// and the identity the provider returned.
type ResolveInput struct {
	Realm       *config.Realm
	ProviderKey config.ProviderKey
	Provider    *config.Provider
	Identity    provider.Identity
	// SealedProviderToken is the provider refresh token sealed for storage
	// (secure.Box); empty stores nothing and keeps the token stored before.
	SealedProviderToken string
}

// LogValue implements slog.LogValuer. The identity holds an email, a name and
// a token, so it is logged through its own LogValue (SEC-13).
func (in ResolveInput) LogValue() slog.Value {
	realm := ""
	if in.Realm != nil {
		realm = string(in.Realm.Name)
	}
	return slog.GroupValue(
		slog.String("realm", realm),
		slog.String("provider", string(in.ProviderKey)),
		slog.Any("identity", in.Identity),
	)
}

var _ slog.LogValuer = ResolveInput{}

// Service resolves identities to users. It is safe for concurrent use.
type Service struct {
	store store.Store
	audit Auditor
	log   *slog.Logger
	clock clock.Clock
	src   secure.Source
}

// NewService returns a Service. log should be made by logx.New.
func NewService(st store.Store, a Auditor, log *slog.Logger, c clock.Clock, src secure.Source) *Service {
	return &Service{store: st, audit: a, log: log, clock: c, src: src}
}

// Resolve returns the user for the identity. Everything it changes, and the
// audit row of an auto-link, is written in one transaction; the audit line is
// logged only after that commits.
func (s *Service) Resolve(ctx context.Context, in ResolveInput) (*store.User, error) {
	if !in.Realm.Enabled || in.Identity.Subject == "" {
		return nil, ErrRefused
	}
	var result store.User
	var after []func()
	err := s.store.Write(ctx, func(tx store.Tx) error {
		after = nil // a transaction that is retried starts over
		rid, err := secure.NewID(s.src, s.clock)
		if err != nil {
			return err
		}
		realm, err := tx.Realms().Ensure(ctx, in.Realm.Name, store.RealmID(rid), s.clock.Now())
		if err != nil {
			return err
		}
		r := &resolution{Service: s, in: in, realm: realm, tx: tx}
		u, err := r.run(ctx)
		if err != nil {
			return err
		}
		result, after = u, r.after
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, f := range after {
		f()
	}
	return &result, nil
}

// resolution is one Resolve call inside its transaction.
type resolution struct {
	*Service
	in    ResolveInput
	realm store.RealmID
	tx    store.Tx
	after []func() // run once the transaction has committed
}

func (r *resolution) stores(attr string) bool {
	return slices.Contains(r.in.Realm.UserData.Attributes, attr)
}

// email returns the email to store, its key and whether it counts as
// verified: only when the attribute is stored, the provider reports it
// verified and the provider is trusted.
func (r *resolution) email() (email, key string, verified bool) {
	id := r.in.Identity
	if !r.stores("email") || strings.TrimSpace(id.Email) == "" {
		return "", "", false
	}
	return id.Email, emailKey(id.Email), id.EmailVerified && r.in.Provider.TrustEmail
}

func (r *resolution) run(ctx context.Context) (store.User, error) {
	ident, err := r.tx.Identities().Find(ctx, r.realm, r.in.ProviderKey, r.in.Identity.Subject)
	switch {
	case err == nil:
		return r.known(ctx, ident)
	case errors.Is(err, store.ErrNotFound):
		return r.fresh(ctx)
	}
	return store.User{}, err
}

// known handles an identity seen before: the identity row is updated at every
// login, and the user follows it only with sync_mode force.
func (r *resolution) known(ctx context.Context, ident store.Identity) (store.User, error) {
	u, err := r.tx.Users().Get(ctx, r.realm, ident.UserID)
	if err != nil {
		return store.User{}, err
	}
	if !u.DisabledAt.IsZero() {
		return store.User{}, ErrDisabled
	}
	email, key, verified := r.email()
	ident.Email, ident.EmailVerified = email, verified
	if err := r.tx.Identities().Update(ctx, ident); err != nil {
		return store.User{}, err
	}
	if err := r.keepToken(ctx, ident.ID); err != nil {
		return store.User{}, err
	}
	if r.in.Provider.SyncMode != "force" {
		return u, nil
	}

	changed := false
	if email != "" && (email != u.Email || verified != u.EmailVerified) {
		conflict := false
		if verified && (key != u.EmailKey || !u.EmailVerified) {
			holder, err := r.tx.Users().FindVerifiedByEmailKey(ctx, r.realm, key)
			switch {
			case err == nil && holder.ID != u.ID:
				conflict = true
			case err != nil && !errors.Is(err, store.ErrNotFound):
				return store.User{}, err
			}
		}
		if conflict {
			// The old email is kept; the conflict is logged after the commit.
			uid, provKey := u.ID, r.in.ProviderKey
			r.after = append(r.after, func() {
				r.log.LogAttrs(ctx, slog.LevelWarn, "email conflict: the new email is held by another verified user, the old one is kept",
					slog.String("user_id", string(uid)), slog.String("provider", string(provKey)))
			})
		} else {
			u.Email, u.EmailKey, u.EmailVerified = email, key, verified
			changed = true
		}
	}
	if r.stores("name") {
		name := r.in.Identity.Name
		if (name != "" || !r.in.Realm.UserData.KeepNameIfMissing) && name != u.Name {
			u.Name = name
			changed = true
		}
	}
	if changed {
		u.UpdatedAt = r.clock.Now()
		if err := r.tx.Users().Update(ctx, u); err != nil {
			return store.User{}, err
		}
	}
	return u, nil
}

// fresh handles an identity never seen: link it to the user that holds its
// verified email when the auto-link rules allow, otherwise create a user.
func (r *resolution) fresh(ctx context.Context) (store.User, error) {
	email, key, verified := r.email()
	var holder *store.User
	if verified {
		h, err := r.tx.Users().FindVerifiedByEmailKey(ctx, r.realm, key)
		switch {
		case err == nil:
			holder = &h
		case !errors.Is(err, store.ErrNotFound):
			return store.User{}, err
		}
	}

	if holder != nil && r.in.Provider.AutoLink && r.linkDomain(key) {
		if !holder.DisabledAt.IsZero() {
			return store.User{}, ErrDisabled
		}
		if err := r.createIdentity(ctx, holder.ID, email, verified); err != nil {
			return store.User{}, err
		}
		publish, err := r.audit.WriteTx(ctx, r.tx, audit.Event{
			Realm: r.realm, Actor: "provider:" + string(r.in.ProviderKey), Action: ActionAutoLink,
			User: holder.ID, Details: map[string]any{"provider": string(r.in.ProviderKey)},
		})
		if err != nil {
			return store.User{}, err
		}
		r.after = append(r.after, publish)
		return *holder, nil
	}

	id, err := r.newUserID()
	if err != nil {
		return store.User{}, err
	}
	now := r.clock.Now()
	u := store.User{
		ID: store.UserID(id), RealmID: r.realm, Email: email, EmailKey: key,
		// One verified user per email: the second holder is not verified.
		EmailVerified: verified && holder == nil,
		CreatedAt:     now, UpdatedAt: now,
	}
	if r.stores("name") {
		u.Name = r.in.Identity.Name
	}
	if err := r.tx.Users().Create(ctx, u); err != nil {
		return store.User{}, err
	}
	if err := r.createIdentity(ctx, u.ID, email, u.EmailVerified); err != nil {
		return store.User{}, err
	}
	return u, nil
}

func (r *resolution) createIdentity(ctx context.Context, uid store.UserID, email string, verified bool) error {
	id, err := secure.NewID(r.src, r.clock)
	if err != nil {
		return err
	}
	err = r.tx.Identities().Create(ctx, store.Identity{
		ID: store.IdentityID(id), RealmID: r.realm, UserID: uid, Provider: r.in.ProviderKey,
		ProviderSub: r.in.Identity.Subject, Email: email, EmailVerified: verified,
		CreatedAt: r.clock.Now(),
	})
	if err != nil {
		return fmt.Errorf("user: create identity: %w", err)
	}
	return r.keepToken(ctx, store.IdentityID(id))
}

// keepToken stores the sealed provider token of the login on the identity,
// replacing the one stored before; without one the stored token stays.
func (r *resolution) keepToken(ctx context.Context, id store.IdentityID) error {
	if r.in.SealedProviderToken == "" {
		return nil
	}
	return r.tx.Identities().SetProviderToken(ctx, r.realm, id, r.in.SealedProviderToken)
}

// linkDomain reports whether the domain of an email key is on the realm's
// auto-link list.
func (r *resolution) linkDomain(key string) bool {
	at := strings.LastIndexByte(key, '@')
	if at < 0 {
		return false
	}
	domain := key[at+1:]
	return slices.ContainsFunc(r.in.Realm.UserData.AutoLinkDomains, func(d string) bool {
		return strings.EqualFold(strings.TrimSpace(d), domain)
	})
}

// emailKey is the comparison form of an email: trimmed and lowercased, with
// nothing provider specific (no dot or plus-address handling).
func emailKey(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// newUserID makes the id of a user this resolution creates, in the format of
// the realm's user_data.id_format; empty means the default, uuid. Only user
// ids follow the option: identities and everything else stay ULIDs.
func (r *resolution) newUserID() (string, error) {
	switch f := r.in.Realm.UserData.IDFormat; f {
	case "", config.IDFormatUUID:
		return secure.NewUUID(r.src)
	case config.IDFormatULID:
		return secure.NewID(r.src, r.clock)
	default:
		return "", fmt.Errorf("user: unknown user id format %q", f)
	}
}
