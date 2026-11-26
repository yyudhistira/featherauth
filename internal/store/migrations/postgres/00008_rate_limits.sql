-- +goose Up
-- Shared rate limit windows (FR-53): one row for each client key and minute of
-- the service clock, with the requests the key made in that minute. A request
-- raises the count with one statement; the hourly job deletes the windows that
-- started before the current minute.
CREATE TABLE rate_limits (
    key          TEXT   NOT NULL,
    window_start BIGINT NOT NULL,
    count        BIGINT NOT NULL,
    PRIMARY KEY (key, window_start)
);

-- +goose Down
DROP TABLE rate_limits;
