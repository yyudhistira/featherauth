package token

import (
	"context"
	"errors"
	"fmt"

	"github.com/yyudhistira/featherauth/internal/clock"
	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
	"github.com/yyudhistira/featherauth/internal/store"
)

// RefreshInput is a refresh grant request after client authentication.
type RefreshInput struct {
	Realm  *config.Realm
	Client *config.Client
	Token  string
	// DPoP is the DPoP header of the request (FR-44); no header means no proof.
	DPoP DPoPRequest
}

// Refresher exchanges refresh tokens for new tokens. It is safe for
// concurrent use: every request runs in one write transaction, and writers
// queue in the store.
type Refresher struct {
	store store.Store
	clock clock.Clock
	minter
}

// NewRefresher returns a Refresher that keeps its rows in st, signs with
// issuer, reads time from c and random values from src.
func NewRefresher(st store.Store, issuer *Issuer, c clock.Clock, src secure.Source) *Refresher {
	return &Refresher{store: st, clock: c, minter: minter{issuer, c, src}}
}

// Refresh checks a refresh token and returns new tokens, as in "Sessions and
// refresh rotation" of the design. Every refusal is an invalid_grant
// *GrantError; a token that proves a theft (a rotated token presented after
// the grace window or after a successor was used, or a revoked successor)
// also revokes its session, and that revocation is committed.
func (f *Refresher) Refresh(ctx context.Context, in RefreshInput) (*Grant, error) {
	refuse := func() (*Grant, error) { return nil, grantErr(CodeInvalidGrant, "invalid refresh token") }
	if !in.Realm.Enabled {
		return refuse()
	}
	cid, err := clientID(in.Realm, in.Client)
	if err != nil {
		return refuse()
	}

	var grant *Grant
	var refused bool
	var reuse *Reuse
	err = f.store.Write(ctx, func(tx store.Tx) error {
		// The store runs this again after a deadlock, so a run starts with no
		// result of an earlier one.
		grant, refused, reuse = nil, false, nil
		rid, err := tx.Realms().Find(ctx, in.Realm.Name)
		if errors.Is(err, store.ErrNotFound) {
			refused = true
			return nil
		}
		if err != nil {
			return err
		}
		repo := tx.RefreshTokens()
		now := f.clock.Now()
		rt, err := repo.FindByHash(ctx, rid, secure.HashOf(in.Token))
		if errors.Is(err, store.ErrNotFound) {
			refused = true
			return nil
		}
		if err != nil {
			return err
		}
		// Another client's token is refused and left alone.
		if rt.ClientID != cid {
			refused = true
			return nil
		}
		u, err := tx.Users().Get(ctx, rid, rt.UserID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && !u.DisabledAt.IsZero()) {
			refused = true
			return nil
		}
		if err != nil {
			return err
		}
		sub := Subject{ID: UserID(u.ID), Email: u.Email, EmailVerified: u.EmailVerified, Name: u.Name}
		sess := Session{
			ID: SessionID(rt.SessionID), StartedAt: rt.SessionStartedAt, AuthTime: rt.AuthTime, Nonce: rt.Nonce,
			SSOIDHash: rt.SSOIDHash,
		}
		// revokeSession revokes the session of the presented token and keeps
		// what the revocation ended, for the reuse record (SEC-25).
		revokeSession := func() error {
			refused = true
			ended, err := repo.RevokeSession(ctx, rid, rt.SessionID, now)
			if err != nil {
				return err
			}
			if err := store.QueueLogouts(ctx, tx, in.Realm, rid, ended.Sessions, f.clock, f.src); err != nil {
				return err
			}
			reuse = &Reuse{
				Realm: rid, User: UserID(rt.UserID), Client: rt.ClientID,
				Session: SessionID(rt.SessionID), Kind: ReuseRefreshToken, Ended: ended.Tokens > 0,
			}
			return nil
		}

		switch {
		case !rt.RevokedAt.IsZero():
			// A token revoked by logout has its whole session revoked
			// already, so this changes nothing there; a successor revoked
			// because another was used is a stale copy, which is a theft.
			return revokeSession()
		case rt.ReplacedBy != "":
			// The window runs from the first rotation, and the grace check
			// comes before the token's own expiry: the window is for retries
			// after a lost response, so it depends on neither this token's
			// nor its first successor's expiry. An unrevoked rotated token
			// has no used successor (using one revokes it). A first
			// successor that is gone (deleted as expired) means the window
			// is long over.
			first, err := repo.FindByID(ctx, rid, rt.ReplacedBy)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			if err != nil || !now.Before(first.CreatedAt.Add(in.Realm.Tokens.RefreshReuseGrace.Std())) {
				return revokeSession()
			}
			// A bound token needs a proof of its own key before its successor is
			// returned, checked as at any other refresh (FR-44). An unbound one is
			// unchanged, except on a required client, where it is checked as a
			// normal unbound refresh of a required client: required wins.
			graced := binding{}
			if rt.DPoPJKT != "" || in.Client.DPoP == config.DPoPRequired {
				graced, err = bindRefresh(ctx, tx, in.Client, rt, in.DPoP, now)
				if err != nil {
					return err
				}
			}
			grant, err = f.successor(ctx, tx, rid, in, sub, sess, nil, graced)
			return err
		case !rt.ExpiresAt.After(now):
			refused = true
			return nil
		case !in.Client.Rotates():
			// The same token goes back, so a JWT keeps its original exp
			// claim while the stored expiry moves; validity is decided from
			// the stored expiry only.
			exp := refreshExpiry(in.Client.Lifetimes(), now, rt.SessionStartedAt)
			if !exp.After(now) {
				refused = true
				return nil
			}
			b, err := bindRefresh(ctx, tx, in.Client, rt, in.DPoP, now)
			if err != nil {
				return err
			}
			sess.Jkt = b.access
			tk, err := f.sign(in.Realm, in.Client, sub, sess)
			if err != nil {
				return err
			}
			if err := repo.Extend(ctx, rid, rt.ID, exp); err != nil {
				return err
			}
			grant = f.result(tk, in.Token, exp, b.access != "")
			return nil
		default:
			// Using a token proves it is the live one: every other token of
			// the session (its siblings and its predecessors) goes.
			b, err := bindRefresh(ctx, tx, in.Client, rt, in.DPoP, now)
			if err != nil {
				return err
			}
			if err := repo.RevokeOthers(ctx, rid, rt.SessionID, rt.ID, now); err != nil {
				return err
			}
			grant, err = f.successor(ctx, tx, rid, in, sub, sess, &rt, b)
			return err
		}
	})
	var ge *GrantError
	switch {
	case errors.As(err, &ge):
		return nil, ge
	case err != nil:
		return nil, fmt.Errorf("token: refresh: %w", err)
	case reuse != nil:
		refusal := grantErr(CodeInvalidGrant, "invalid refresh token")
		refusal.Reuse = reuse
		return nil, refusal
	case refused:
		return refuse()
	}
	return grant, nil
}

// successor signs new tokens and stores a new refresh token of the session;
// when old is not nil it is marked as replaced by it.
func (f *Refresher) successor(ctx context.Context, tx store.Tx, rid store.RealmID, in RefreshInput, sub Subject, sess Session, old *store.RefreshToken, b binding) (*Grant, error) {
	sess.Jkt = b.access
	tk, err := f.sign(in.Realm, in.Client, sub, sess)
	if err != nil {
		return nil, err
	}
	raw, row, err := f.newRefresh(rid, in.Realm, in.Client, sub, sess, b.refresh)
	if err != nil {
		return nil, err
	}
	if err := tx.RefreshTokens().Insert(ctx, row); err != nil {
		return nil, err
	}
	if old != nil {
		if err := tx.RefreshTokens().MarkReplaced(ctx, old.ID, row.ID); err != nil {
			return nil, err
		}
	}
	return f.result(tk, raw, row.ExpiresAt, b.access != ""), nil
}
