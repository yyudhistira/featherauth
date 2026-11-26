-- +goose Up
-- A login has at most one handoff (SEC-23). Older rows for the same login are
-- replaced by the newest one before the index is added; handoffs live 60
-- seconds, so only a callback posted twice in that time has any.
DELETE FROM callback_handoffs WHERE rowid NOT IN (SELECT MAX(rowid) FROM callback_handoffs GROUP BY auth_request_id);
CREATE UNIQUE INDEX callback_handoffs_auth_request_id ON callback_handoffs (auth_request_id);

-- +goose Down
DROP INDEX callback_handoffs_auth_request_id;
