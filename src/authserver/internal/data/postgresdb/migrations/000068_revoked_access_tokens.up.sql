-- An access token without a grant is revoked by its jti (#676 decision 1). See the sqlite migration
-- of the same number for why, for the six questions and for what the index serves. PostgreSQL
-- compares strings byte-wise, so the jti needs no collation pin.
CREATE TABLE revoked_access_tokens (
    jti character varying(64) NOT NULL PRIMARY KEY,
    expires_at timestamp(6) without time zone NOT NULL
);
CREATE INDEX idx_revoked_access_tokens_expires_at ON revoked_access_tokens(expires_at);
