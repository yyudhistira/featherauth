-- +goose Up
-- Browser sessions of single sign-on (FR-45, SEC-37): one row for each login that
-- started one. id_hash is the SHA-256 of the random cookie value; the value itself
-- is never stored. user_id has a cascade, so a deleted user's sessions go with
-- it. identity_id has no foreign key: an unlinked identity's sessions are deleted
-- by the code that unlinks it. Expired rows are deleted by the hourly job.
CREATE TABLE sso_sessions (
    id_hash      TEXT   NOT NULL PRIMARY KEY,
    realm_id     TEXT   NOT NULL,
    user_id      TEXT   NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    identity_id  TEXT   NOT NULL,
    provider     TEXT   NOT NULL,
    auth_time    BIGINT NOT NULL,
    created_at   BIGINT NOT NULL,
    last_used_at BIGINT NOT NULL,
    expires_at   BIGINT NOT NULL
);
CREATE INDEX sso_sessions_user_id ON sso_sessions (user_id);

-- The browser session a login started (FR-45), carried to the token session that
-- the login's code makes, and copied to its successors. NULL when none.
ALTER TABLE auth_codes ADD COLUMN sso_id_hash TEXT;
ALTER TABLE refresh_tokens ADD COLUMN sso_id_hash TEXT;

-- +goose Down
ALTER TABLE refresh_tokens DROP COLUMN sso_id_hash;
ALTER TABLE auth_codes DROP COLUMN sso_id_hash;
DROP TABLE sso_sessions;
