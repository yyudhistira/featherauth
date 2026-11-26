-- +goose Up
CREATE TABLE realms (
    id         TEXT    NOT NULL PRIMARY KEY,
    name       TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX realms_name ON realms (name);

CREATE TABLE users (
    realm_id       TEXT    NOT NULL REFERENCES realms (id),
    id             TEXT    NOT NULL PRIMARY KEY,
    email          TEXT,
    email_key      TEXT,
    email_verified INTEGER NOT NULL,
    name           TEXT,
    disabled_at    INTEGER,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
);
CREATE UNIQUE INDEX users_verified_email_key ON users (realm_id, email_key) WHERE email_verified = 1;
CREATE INDEX users_email_key ON users (realm_id, email_key);

CREATE TABLE identities (
    id                         TEXT    NOT NULL PRIMARY KEY,
    realm_id                   TEXT    NOT NULL REFERENCES realms (id),
    user_id                    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider                   TEXT    NOT NULL,
    provider_sub               TEXT    NOT NULL,
    email                      TEXT    NOT NULL,
    email_verified             INTEGER NOT NULL,
    provider_refresh_token_enc TEXT,
    created_at                 INTEGER NOT NULL
);
CREATE UNIQUE INDEX identities_provider_sub ON identities (realm_id, provider, provider_sub);

CREATE TABLE auth_requests (
    id                     TEXT    NOT NULL PRIMARY KEY,
    realm_id               TEXT    NOT NULL,
    client_id              TEXT    NOT NULL,
    redirect_uri           TEXT    NOT NULL,
    client_state           TEXT    NOT NULL,
    nonce                  TEXT    NOT NULL,
    provider_nonce         TEXT    NOT NULL,
    code_challenge         TEXT    NOT NULL,
    response_mode          TEXT    NOT NULL,
    max_age                INTEGER,
    provider               TEXT    NOT NULL,
    provider_pkce_verifier TEXT    NOT NULL,
    expires_at             INTEGER NOT NULL
);

CREATE TABLE auth_codes (
    code_hash          TEXT    NOT NULL PRIMARY KEY,
    realm_id           TEXT    NOT NULL,
    user_id            TEXT    NOT NULL,
    session_id         TEXT    NOT NULL,
    session_started_at INTEGER NOT NULL,
    client_id          TEXT    NOT NULL,
    redirect_uri       TEXT    NOT NULL,
    code_challenge     TEXT    NOT NULL,
    nonce              TEXT    NOT NULL,
    auth_time          INTEGER NOT NULL,
    expires_at         INTEGER NOT NULL,
    used_at            INTEGER
);

CREATE TABLE callback_handoffs (
    id_hash         TEXT    NOT NULL PRIMARY KEY,
    auth_request_id TEXT    NOT NULL,
    payload         TEXT    NOT NULL,
    expires_at      INTEGER NOT NULL
);

CREATE TABLE refresh_tokens (
    id                 TEXT    NOT NULL PRIMARY KEY,
    realm_id           TEXT    NOT NULL,
    user_id            TEXT    NOT NULL,
    client_id          TEXT    NOT NULL,
    token_hash         TEXT    NOT NULL,
    session_id         TEXT    NOT NULL,
    session_started_at INTEGER NOT NULL,
    auth_time          INTEGER NOT NULL,
    nonce              TEXT,
    replaced_by        TEXT,
    expires_at         INTEGER NOT NULL,
    revoked_at         INTEGER,
    created_at         INTEGER NOT NULL
);
CREATE UNIQUE INDEX refresh_tokens_token_hash ON refresh_tokens (token_hash);
CREATE INDEX refresh_tokens_session_id ON refresh_tokens (session_id);
CREATE INDEX refresh_tokens_user_id ON refresh_tokens (user_id);

CREATE TABLE audit_events (
    id         TEXT    NOT NULL PRIMARY KEY,
    realm_id   TEXT    NOT NULL,
    actor      TEXT    NOT NULL,
    action     TEXT    NOT NULL,
    user_id    TEXT,
    details    TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX audit_events_realm_created ON audit_events (realm_id, created_at);

-- +goose Down
DROP TABLE audit_events;
DROP TABLE refresh_tokens;
DROP TABLE callback_handoffs;
DROP TABLE auth_codes;
DROP TABLE auth_requests;
DROP TABLE identities;
DROP TABLE users;
DROP TABLE realms;
