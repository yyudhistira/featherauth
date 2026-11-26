package store

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
)

var (
	_ AuthRequests   = authRequestRepo{}
	_ AuthCodes      = authCodeRepo{}
	_ Handoffs       = handoffRepo{}
	_ ProviderEvents = providerEventRepo{}

	_ slog.LogValuer = AuthRequest{}
	_ slog.LogValuer = AuthCode{}
	_ slog.LogValuer = Handoff{}
)

// LogValue logs the realm, client, provider and expiry only: never the id
// (it is the state sent to the provider), the client state, the nonces, the
// PKCE challenge or verifier, or the redirect URI.
func (r AuthRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("realm_id", string(r.RealmID)),
		slog.String("client_id", string(r.ClientID)),
		slog.String("provider", string(r.Provider)),
		slog.Time("expires_at", r.ExpiresAt),
	)
}

// LogValue logs ids and times only: never the code hash, the nonce, the PKCE
// challenge or the redirect URI.
func (c AuthCode) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("realm_id", string(c.RealmID)),
		slog.String("user_id", string(c.UserID)),
		slog.String("session_id", string(c.SessionID)),
		slog.String("client_id", string(c.ClientID)),
		slog.Time("expires_at", c.ExpiresAt),
		slog.Bool("used", !c.UsedAt.IsZero()),
	)
}

// LogValue logs the expiry only: never the id hash, the auth request id or the
// payload.
func (h Handoff) LogValue() slog.Value {
	return slog.GroupValue(slog.Time("expires_at", h.ExpiresAt))
}

type (
	authRequestRepo   struct{ tx dbtx }
	authCodeRepo      struct{ tx dbtx }
	handoffRepo       struct{ tx dbtx }
	providerEventRepo struct{ tx dbtx }
)

func expired(now, expiresAt time.Time) bool { return !now.Before(expiresAt) }

const authRequestColumns = `id, realm_id, client_id, redirect_uri, client_state, nonce, provider_nonce,
	code_challenge, response_mode, max_age, provider, provider_pkce_verifier, expires_at`

func (r authRequestRepo) Create(ctx context.Context, a AuthRequest) error {
	var maxAge sql.NullInt64
	if a.MaxAge != nil {
		maxAge = sql.NullInt64{Int64: int64(*a.MaxAge / time.Second), Valid: true}
	}
	_, err := r.tx.ExecContext(ctx,
		`INSERT INTO auth_requests (`+authRequestColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(a.ID), string(a.RealmID), string(a.ClientID), a.RedirectURI, a.ClientState, a.Nonce,
		a.ProviderNonce, a.CodeChallenge, a.ResponseMode, maxAge, string(a.Provider),
		a.ProviderPKCEVerifier, unix(a.ExpiresAt))
	return mapWriteErr(err)
}

func (r authRequestRepo) Get(ctx context.Context, id AuthRequestID) (AuthRequest, error) {
	var (
		a                       AuthRequest
		aid, realm, client, pr  string
		redirect, cstate, nonce string
		pnonce, challenge, mode string
		verifier                string
		maxAge                  sql.NullInt64
		expires                 int64
	)
	err := r.tx.QueryRowContext(ctx,
		`SELECT `+authRequestColumns+` FROM auth_requests WHERE id = ?`+rowLock(r.tx), string(id)).
		Scan(&aid, &realm, &client, &redirect, &cstate, &nonce, &pnonce, &challenge, &mode, &maxAge, &pr, &verifier, &expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthRequest{}, ErrNotFound
		}
		return AuthRequest{}, err
	}
	a = AuthRequest{
		ID: AuthRequestID(aid), RealmID: RealmID(realm), ClientID: config.ClientID(client),
		RedirectURI: redirect, ClientState: cstate, Nonce: nonce, ProviderNonce: pnonce,
		CodeChallenge: challenge, ResponseMode: mode, Provider: config.ProviderKey(pr),
		ProviderPKCEVerifier: verifier, ExpiresAt: fromUnix(expires),
	}
	if maxAge.Valid {
		d := time.Duration(maxAge.Int64) * time.Second
		a.MaxAge = &d
	}
	return a, nil
}

func (r authRequestRepo) Delete(ctx context.Context, id AuthRequestID) error {
	return expectOne(r.tx.ExecContext(ctx, `DELETE FROM auth_requests WHERE id = ?`, string(id)))
}

const authCodeColumns = `code_hash, realm_id, user_id, session_id, session_started_at, client_id,
	redirect_uri, code_challenge, nonce, auth_time, expires_at, used_at, sso_id_hash`

func (r authCodeRepo) Create(ctx context.Context, c AuthCode) error {
	_, err := r.tx.ExecContext(ctx,
		`INSERT INTO auth_codes (`+authCodeColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(c.CodeHash), string(c.RealmID), string(c.UserID), string(c.SessionID),
		unix(c.SessionStartedAt), string(c.ClientID), c.RedirectURI, c.CodeChallenge, c.Nonce,
		unix(c.AuthTime), unix(c.ExpiresAt), nullTime(c.UsedAt), nullStr(string(c.SSOIDHash)))
	return mapWriteErr(err)
}

func (r authCodeRepo) Consume(ctx context.Context, hash secure.Hash, now time.Time) (AuthCode, error) {
	var (
		hs, realm, user, sess, client string
		redirect, challenge, nonce    string
		started, authTime, expires    int64
		used                          sql.NullInt64
		sso                           sql.NullString
	)
	err := r.tx.QueryRowContext(ctx,
		`SELECT `+authCodeColumns+` FROM auth_codes WHERE code_hash = ?`+rowLock(r.tx), string(hash)).
		Scan(&hs, &realm, &user, &sess, &started, &client, &redirect, &challenge, &nonce, &authTime, &expires, &used, &sso)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthCode{}, ErrNotFound
		}
		return AuthCode{}, err
	}
	if used.Valid {
		return AuthCode{}, &UsedError{SessionID: SessionID(sess), UserID: UserID(user), ClientID: config.ClientID(client)}
	}
	if expired(now, fromUnix(expires)) {
		return AuthCode{}, ErrExpired
	}
	// The used_at IS NULL guard keeps the check and the mark one atomic step
	// even if the caller's transaction were not the only writer.
	res, err := r.tx.ExecContext(ctx,
		`UPDATE auth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL`, unix(now), string(hash))
	if err := expectOne(res, err); err != nil {
		if errors.Is(err, ErrNotFound) {
			return AuthCode{}, &UsedError{SessionID: SessionID(sess), UserID: UserID(user), ClientID: config.ClientID(client)}
		}
		return AuthCode{}, err
	}
	return AuthCode{
		CodeHash: secure.Hash(hs), RealmID: RealmID(realm), UserID: UserID(user), SessionID: SessionID(sess),
		SessionStartedAt: fromUnix(started), ClientID: config.ClientID(client), RedirectURI: redirect,
		CodeChallenge: challenge, Nonce: nonce, AuthTime: fromUnix(authTime),
		ExpiresAt: fromUnix(expires), UsedAt: now.UTC().Truncate(time.Second), SSOIDHash: secure.Hash(sso.String),
	}, nil
}

// Create stores a handoff. A login has one handoff: an earlier one of the same
// login is replaced in this transaction, and its id stops working. A repeated
// id still gives ErrConflict.
func (r handoffRepo) Create(ctx context.Context, h Handoff) error {
	if _, err := r.tx.ExecContext(ctx,
		`DELETE FROM callback_handoffs WHERE auth_request_id = ? AND id_hash <> ?`,
		string(h.AuthRequestID), string(h.IDHash)); err != nil {
		return mapWriteErr(err)
	}
	_, err := r.tx.ExecContext(ctx,
		`INSERT INTO callback_handoffs (id_hash, auth_request_id, payload, expires_at) VALUES (?, ?, ?, ?)`,
		string(h.IDHash), string(h.AuthRequestID), h.Payload, unix(h.ExpiresAt))
	return mapWriteErr(err)
}

func (r handoffRepo) Take(ctx context.Context, hash secure.Hash, now time.Time) (Handoff, error) {
	var (
		id, req, payload string
		expires          int64
	)
	err := r.tx.QueryRowContext(ctx,
		`SELECT id_hash, auth_request_id, payload, expires_at FROM callback_handoffs WHERE id_hash = ?`+rowLock(r.tx),
		string(hash)).Scan(&id, &req, &payload, &expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Handoff{}, ErrNotFound
		}
		return Handoff{}, err
	}
	if expired(now, fromUnix(expires)) {
		return Handoff{}, ErrExpired
	}
	if err := expectOne(r.tx.ExecContext(ctx, `DELETE FROM callback_handoffs WHERE id_hash = ?`, string(hash))); err != nil {
		return Handoff{}, err
	}
	return Handoff{IDHash: secure.Hash(id), AuthRequestID: AuthRequestID(req), Payload: payload, ExpiresAt: fromUnix(expires)}, nil
}

func rowsAffected(res sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r authRequestRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	return rowsAffected(r.tx.ExecContext(ctx, `DELETE FROM auth_requests WHERE expires_at <= ?`, unix(now)))
}

func (r authCodeRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	return rowsAffected(r.tx.ExecContext(ctx, `DELETE FROM auth_codes WHERE expires_at <= ?`, unix(now)))
}

func (r handoffRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	return rowsAffected(r.tx.ExecContext(ctx, `DELETE FROM callback_handoffs WHERE expires_at <= ?`, unix(now)))
}

// Remember inserts the row unless the same realm, provider and id hash has one
// already; the insert reports whether it wrote, so a repeat is not an error.
func (r providerEventRepo) Remember(ctx context.Context, realm RealmID, prov config.ProviderKey, idHash secure.Hash, expiresAt time.Time) (bool, error) {
	res, err := r.tx.ExecContext(ctx,
		`INSERT INTO provider_event_ids (realm_id, provider, id_hash, expires_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT (realm_id, provider, id_hash) DO NOTHING`,
		string(realm), string(prov), string(idHash), unix(expiresAt))
	if err != nil {
		return false, mapWriteErr(err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// DeleteExpired removes the provider event ids that are strictly past their
// expiry at now, in every realm. An id at exactly its expiry is kept: an event
// still accepted at that instant must be recognised as a repeat.
func (r providerEventRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	return rowsAffected(r.tx.ExecContext(ctx, `DELETE FROM provider_event_ids WHERE expires_at < ?`, unix(now)))
}
