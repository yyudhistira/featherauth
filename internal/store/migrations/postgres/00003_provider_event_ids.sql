-- +goose Up
-- Provider events already acted on (SEC-27): one row for each id of an event,
-- kept until the event's expiry and deleted by the hourly job.
CREATE TABLE provider_event_ids (
    realm_id   TEXT   NOT NULL,
    provider   TEXT   NOT NULL,
    id_hash    TEXT   NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (realm_id, provider, id_hash)
);

-- +goose Down
DROP TABLE provider_event_ids;
