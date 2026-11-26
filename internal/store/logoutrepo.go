package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/yyudhistira/featherauth/internal/config"
)

// logoutRetry is the wait after each try: the next try of a row is due this long
// after its first, second, third and fourth try. A row is tried five times in all.
var logoutRetry = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}

// nextTry returns when the try after the tries-th try is due: now plus the wait
// after that try, and now itself after the last one.
func nextTry(now time.Time, tries int) time.Time {
	if tries >= 1 && tries <= len(logoutRetry) {
		return now.Add(logoutRetry[tries-1])
	}
	return now
}

// logoutRepo is the logout_notifications table.
type logoutRepo struct{ q dbtx }

func (r logoutRepo) Enqueue(ctx context.Context, n LogoutNotification) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO logout_notifications (id, realm_id, client_id, user_id, session_id, attempts, next_attempt_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		string(n.ID), string(n.RealmID), string(n.ClientID), string(n.UserID), string(n.SessionID),
		n.Attempts, unix(n.NextAttemptAt), unix(n.CreatedAt))
	return mapWriteErr(err)
}

func (r logoutRepo) Claim(ctx context.Context, now time.Time, limit int) ([]LogoutNotification, error) {
	// On Postgres a row another worker's transaction holds is skipped, so two
	// workers take different rows; SQLite serialises its writers already.
	lock := rowLock(r.q)
	if lock != "" {
		lock += " SKIP LOCKED"
	}
	rows, err := r.q.QueryContext(ctx,
		`SELECT id, realm_id, client_id, user_id, session_id, attempts, next_attempt_at, created_at
		 FROM logout_notifications WHERE next_attempt_at <= ? ORDER BY next_attempt_at, id LIMIT ?`+lock,
		unix(now), limit)
	if err != nil {
		return nil, err
	}
	// The rows are read before any update: the connection can run one
	// statement at a time.
	out, err := scanLogouts(rows)
	if err != nil {
		return nil, err
	}
	for _, n := range out {
		tries := n.Attempts + 1
		if _, err := r.q.ExecContext(ctx,
			`UPDATE logout_notifications SET attempts = ?, next_attempt_at = ? WHERE id = ?`,
			tries, unix(nextTry(now, tries)), string(n.ID)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r logoutRepo) Done(ctx context.Context, id LogoutNotificationID) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM logout_notifications WHERE id = ?`, string(id))
	return err
}

func (r logoutRepo) Drop(ctx context.Context, id LogoutNotificationID) error {
	return r.Done(ctx, id)
}

// scanLogouts reads every row and closes the result set.
func scanLogouts(rows *sql.Rows) ([]LogoutNotification, error) {
	defer func() { _ = rows.Close() }()
	var out []LogoutNotification
	for rows.Next() {
		var (
			id, realm, client, user, session string
			attempts                         int
			next, created                    int64
		)
		if err := rows.Scan(&id, &realm, &client, &user, &session, &attempts, &next, &created); err != nil {
			return nil, err
		}
		out = append(out, LogoutNotification{
			ID: LogoutNotificationID(id), RealmID: RealmID(realm), ClientID: config.ClientID(client), UserID: UserID(user),
			SessionID: SessionID(session), Attempts: attempts, NextAttemptAt: fromUnix(next), CreatedAt: fromUnix(created),
		})
	}
	return out, rows.Err()
}
