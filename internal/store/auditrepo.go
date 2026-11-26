package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

var _ Audit = auditRepo{}

type auditRepo struct{ tx dbtx }

func (r auditRepo) Insert(ctx context.Context, e AuditEvent) error {
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("store: encoding audit details: %w", err)
	}
	_, err = r.tx.ExecContext(ctx,
		`INSERT INTO audit_events (id, realm_id, actor, action, user_id, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.ID, string(e.RealmID), e.Actor, e.Action, nullStr(string(e.UserID)), string(raw), unix(e.CreatedAt))
	return mapWriteErr(err)
}

func (r auditRepo) List(ctx context.Context, realm RealmID, since time.Time) ([]AuditEvent, error) {
	rows, err := r.tx.QueryContext(ctx,
		`SELECT id, realm_id, actor, action, user_id, details, created_at FROM audit_events
		 WHERE realm_id = ? AND created_at >= ? ORDER BY created_at, id`, string(realm), unix(since))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEvent
	for rows.Next() {
		var (
			e                  AuditEvent
			realmID, user, raw sql.NullString
			created            int64
		)
		if err := rows.Scan(&e.ID, &realmID, &e.Actor, &e.Action, &user, &raw, &created); err != nil {
			return nil, err
		}
		e.RealmID, e.UserID, e.CreatedAt = RealmID(realmID.String), UserID(user.String), fromUnix(created)
		if err := json.Unmarshal([]byte(raw.String), &e.Details); err != nil {
			return nil, fmt.Errorf("store: decoding audit details of %s: %w", e.ID, err)
		}
		if len(e.Details) == 0 {
			e.Details = nil
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
