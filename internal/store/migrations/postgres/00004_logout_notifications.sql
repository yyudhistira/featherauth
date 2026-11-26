-- +goose Up
-- Back-channel logout tokens still to send (FR-43): one row for each session a
-- revocation ended whose client has backchannel_logout_uri. user_id has no
-- foreign key: the user may be deleted in the same transaction. Rows are not
-- deleted with the user; they are deleted once sent or dropped.
CREATE TABLE logout_notifications (
    id              TEXT   NOT NULL PRIMARY KEY,
    realm_id        TEXT   NOT NULL,
    client_id       TEXT   NOT NULL,
    user_id         TEXT   NOT NULL,
    session_id      TEXT   NOT NULL,
    attempts        BIGINT NOT NULL,
    next_attempt_at BIGINT NOT NULL,
    created_at      BIGINT NOT NULL
);
CREATE INDEX logout_notifications_next_attempt_at ON logout_notifications (next_attempt_at);

-- +goose Down
DROP TABLE logout_notifications;
