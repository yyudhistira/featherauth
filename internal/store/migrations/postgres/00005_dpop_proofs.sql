-- +goose Up
-- DPoP proofs already used (SEC-36): one row for each proof_hash, the SHA-256 of
-- the key thumbprint and the jti of a proof that passed. A row is kept until the
-- hourly job deletes it after expires_at, so a repeated jti is refused.
CREATE TABLE dpop_proofs (
    proof_hash TEXT   NOT NULL PRIMARY KEY,
    expires_at BIGINT NOT NULL
);

-- +goose Down
DROP TABLE dpop_proofs;
