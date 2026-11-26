-- +goose Up
-- A login has at most one handoff (SEC-23). Older rows for the same login are
-- replaced by the newest one before the index is added. Postgres has no rowid,
-- so "newest" is read from expires_at: every handoff lives 60 seconds, so the
-- row that expires last is the one created last (ties by id_hash).
DELETE FROM callback_handoffs AS older
WHERE EXISTS (
    SELECT 1 FROM callback_handoffs AS newer
    WHERE newer.auth_request_id = older.auth_request_id
      AND (newer.expires_at > older.expires_at
           OR (newer.expires_at = older.expires_at AND newer.id_hash > older.id_hash))
);
CREATE UNIQUE INDEX callback_handoffs_auth_request_id ON callback_handoffs (auth_request_id);

-- +goose Down
DROP INDEX callback_handoffs_auth_request_id;
