-- +goose Up
-- The key a session is bound to (FR-44): the JWK SHA-256 thumbprint of the DPoP
-- proof key of a public client's refresh token, copied to its successors. NULL
-- for an unbound token and for every token of a confidential client.
ALTER TABLE refresh_tokens ADD COLUMN dpop_jkt TEXT;

-- +goose Down
ALTER TABLE refresh_tokens DROP COLUMN dpop_jkt;
