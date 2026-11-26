package store

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
	"github.com/yyudhistira/featherauth/internal/secure"
)

var (
	_ RefreshTokens = refreshRepo{}

	_ slog.LogValuer = RefreshToken{}
)

// LogValue logs ids, the client and times only: never the token hash or the
// nonce.
func (r RefreshToken) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", string(r.ID)),
		slog.String("realm_id", string(r.RealmID)),
		slog.String("user_id", string(r.UserID)),
		slog.String("client_id", string(r.ClientID)),
		slog.String("session_id", string(r.SessionID)),
		slog.Time("expires_at", r.ExpiresAt),
		slog.Bool("replaced", r.ReplacedBy != ""),
		slog.Bool("revoked", !r.RevokedAt.IsZero()),
	)
}

type refreshRepo struct{ tx dbtx }

const refreshColumns = `id, realm_id, user_id, client_id, token_hash, session_id, session_started_at,
	auth_time, nonce, replaced_by, expires_at, revoked_at, created_at, dpop_jkt, sso_id_hash`

func (r refreshRepo) Insert(ctx context.Context, t RefreshToken) error {
	_, err := r.tx.ExecContext(ctx,
		`INSERT INTO refresh_tokens (`+refreshColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(t.ID), string(t.RealmID), string(t.UserID), string(t.ClientID), string(t.TokenHash),
		string(t.SessionID), unix(t.SessionStartedAt), unix(t.AuthTime), nullStr(t.Nonce),
		nullStr(string(t.ReplacedBy)), unix(t.ExpiresAt), nullTime(t.RevokedAt), unix(t.CreatedAt), nullStr(t.DPoPJKT),
		nullStr(string(t.SSOIDHash)))
	return mapWriteErr(err)
}

func scanRefresh(s scanner) (RefreshToken, error) {
	var (
		id, realm, user, client, hash, sess string
		started, authTime, expires, created int64
		nonce, replaced, jkt, sso           sql.NullString
		revoked                             sql.NullInt64
	)
	if err := s.Scan(&id, &realm, &user, &client, &hash, &sess, &started, &authTime, &nonce, &replaced,
		&expires, &revoked, &created, &jkt, &sso); err != nil {
		return RefreshToken{}, err
	}
	t := RefreshToken{
		ID: RefreshTokenID(id), RealmID: RealmID(realm), UserID: UserID(user), ClientID: config.ClientID(client),
		TokenHash: secure.Hash(hash), SessionID: SessionID(sess), SessionStartedAt: fromUnix(started),
		AuthTime: fromUnix(authTime), Nonce: nonce.String, ReplacedBy: RefreshTokenID(replaced.String),
		ExpiresAt: fromUnix(expires), CreatedAt: fromUnix(created), DPoPJKT: jkt.String,
		SSOIDHash: secure.Hash(sso.String),
	}
	if revoked.Valid {
		t.RevokedAt = fromUnix(revoked.Int64)
	}
	return t, nil
}

func (r refreshRepo) FindByHash(ctx context.Context, realm RealmID, hash secure.Hash) (RefreshToken, error) {
	t, err := scanRefresh(r.tx.QueryRowContext(ctx,
		`SELECT `+refreshColumns+` FROM refresh_tokens WHERE realm_id = ? AND token_hash = ?`+rowLock(r.tx),
		string(realm), string(hash)))
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	return t, err
}

func (r refreshRepo) FindByID(ctx context.Context, realm RealmID, id RefreshTokenID) (RefreshToken, error) {
	t, err := scanRefresh(r.tx.QueryRowContext(ctx,
		`SELECT `+refreshColumns+` FROM refresh_tokens WHERE realm_id = ? AND id = ?`,
		string(realm), string(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	return t, err
}

func (r refreshRepo) Extend(ctx context.Context, realm RealmID, id RefreshTokenID, expiresAt time.Time) error {
	res, err := r.tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET expires_at = ? WHERE id = ? AND realm_id = ?`,
		unix(expiresAt), string(id), string(realm))
	if err != nil {
		return mapWriteErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r refreshRepo) MarkReplaced(ctx context.Context, id, successor RefreshTokenID) error {
	// The replaced_by IS NULL guard makes the check and the mark one step, so
	// of two concurrent rotations exactly one wins.
	res, err := r.tx.ExecContext(ctx,
		`UPDATE refresh_tokens SET replaced_by = ? WHERE id = ? AND replaced_by IS NULL`,
		string(successor), string(id))
	if err != nil {
		return mapWriteErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 1 {
		return nil
	}
	var one int
	if err := r.tx.QueryRowContext(ctx, `SELECT 1 FROM refresh_tokens WHERE id = ?`, string(id)).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return ErrConflict
}

// collectEnded reads the rows a revoking statement returned, one per refresh
// token it changed or deleted. Tokens counts every row. Sessions lists each
// session once, sorted by id, when one of its rows was live, that is when the row
// had no revoked_at before the statement: with deleted set, the rows carry their
// revoked_at (the value before the delete), else every row was live.
func collectEnded(rows *sql.Rows, deleted bool) (Ended, error) {
	defer func() { _ = rows.Close() }()
	var out Ended
	seen := map[SessionID]bool{}
	for rows.Next() {
		var sess, client, user string
		var revoked sql.NullInt64
		var sso sql.NullString
		var err error
		if deleted {
			err = rows.Scan(&sess, &client, &user, &revoked, &sso)
		} else {
			err = rows.Scan(&sess, &client, &user, &sso)
		}
		if err != nil {
			return Ended{}, err
		}
		out.Tokens++
		if deleted && revoked.Valid {
			continue
		}
		if !seen[SessionID(sess)] {
			seen[SessionID(sess)] = true
			out.Sessions = append(out.Sessions, EndedSession{
				SessionID: SessionID(sess), ClientID: config.ClientID(client), UserID: UserID(user), SSOIDHash: secure.Hash(sso.String),
			})
		}
	}
	if err := rows.Err(); err != nil {
		return Ended{}, err
	}
	slices.SortFunc(out.Sessions, func(a, b EndedSession) int { return strings.Compare(string(a.SessionID), string(b.SessionID)) })
	return out, nil
}

// revoke sets revoked_at on the rows that match where and are not revoked yet, in
// one statement, and returns what it ended. Reading and writing in one statement
// means a session committed by another transaction in the meantime is either
// included or left for its own call, never missed.
func (r refreshRepo) revoke(ctx context.Context, where string, now time.Time, args ...any) (Ended, error) {
	rows, err := r.tx.QueryContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = ? WHERE revoked_at IS NULL AND `+where+` RETURNING session_id, client_id, user_id, sso_id_hash`,
		append([]any{unix(now)}, args...)...)
	if err != nil {
		return Ended{}, err
	}
	return collectEnded(rows, false)
}

func (r refreshRepo) RevokeSession(ctx context.Context, realm RealmID, session SessionID, now time.Time) (Ended, error) {
	return r.revoke(ctx, `realm_id = ? AND session_id = ?`, now, string(realm), string(session))
}

func (r refreshRepo) SessionLive(ctx context.Context, realm RealmID, session SessionID) (bool, error) {
	var live bool
	err := r.tx.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE realm_id = ? AND session_id = ? AND revoked_at IS NULL)`,
		string(realm), string(session)).Scan(&live)
	return live, err
}

func (r refreshRepo) RevokeOthers(ctx context.Context, realm RealmID, session SessionID, keep RefreshTokenID, now time.Time) error {
	_, err := r.revoke(ctx, `realm_id = ? AND session_id = ? AND id <> ?`, now, string(realm), string(session), string(keep))
	return err
}

func (r refreshRepo) RevokeUser(ctx context.Context, realm RealmID, user UserID, now time.Time) (Ended, error) {
	return r.revoke(ctx, `realm_id = ? AND user_id = ?`, now, string(realm), string(user))
}

func (r refreshRepo) DeleteUser(ctx context.Context, realm RealmID, user UserID) (Ended, error) {
	rows, err := r.tx.QueryContext(ctx,
		`DELETE FROM refresh_tokens WHERE realm_id = ? AND user_id = ? RETURNING session_id, client_id, user_id, revoked_at, sso_id_hash`,
		string(realm), string(user))
	if err != nil {
		return Ended{}, err
	}
	return collectEnded(rows, true)
}

func (r refreshRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.tx.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at <= ?`, unix(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// liveSessions returns the sessions of the rows that match where and are live
// at now: a row is live when it is neither revoked nor expired. Each session is
// described by its newest live row, and the result is ordered as UserLiveSessions
// says.
func (r refreshRepo) liveSessions(ctx context.Context, now time.Time, where string, args ...any) ([]LiveSession, error) {
	rows, err := r.tx.QueryContext(ctx,
		`SELECT session_id, client_id, session_started_at, auth_time, created_at, expires_at
		 FROM refresh_tokens WHERE revoked_at IS NULL AND expires_at > ? AND `+where+`
		 ORDER BY session_id, created_at DESC, id DESC`,
		append([]any{unix(now)}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LiveSession
	for rows.Next() {
		var sess, client string
		var started, authTime, created, expires int64
		if err := rows.Scan(&sess, &client, &started, &authTime, &created, &expires); err != nil {
			return nil, err
		}
		if n := len(out); n > 0 && string(out[n-1].SessionID) == sess {
			continue // an older row of a session whose newest row is already taken
		}
		out = append(out, LiveSession{
			SessionID: SessionID(sess), ClientID: config.ClientID(client),
			StartedAt: fromUnix(started), AuthTime: fromUnix(authTime),
			LastUsedAt: fromUnix(created), ExpiresAt: fromUnix(expires),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b LiveSession) int {
		if c := a.StartedAt.Compare(b.StartedAt); c != 0 {
			return c
		}
		return strings.Compare(string(a.SessionID), string(b.SessionID))
	})
	return out, nil
}

func (r refreshRepo) UserLiveSessions(ctx context.Context, realm RealmID, user UserID, now time.Time) ([]LiveSession, error) {
	return r.liveSessions(ctx, now, `realm_id = ? AND user_id = ?`, string(realm), string(user))
}

func (r refreshRepo) RealmLiveSessions(ctx context.Context, realm RealmID, now time.Time) ([]LiveSession, error) {
	return r.liveSessions(ctx, now, `realm_id = ?`, string(realm))
}

func (r refreshRepo) HasSession(ctx context.Context, realm RealmID, user UserID, session SessionID) (bool, error) {
	var ok bool
	err := r.tx.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE realm_id = ? AND user_id = ? AND session_id = ?)`,
		string(realm), string(user), string(session)).Scan(&ok)
	return ok, err
}
