-- An access token without a grant is revoked by its jti (#676 decision 1). A token of the client
-- credentials grant or the implicit flow carries no grant_id, so no refresh token family stands
-- behind it for a revocation to end. Revoking one at /auth/revoke stores its jti here with its
-- expiry, and the access-token liveness check refuses a token without grant_id while its jti is
-- stored, at /userinfo, at the admin and account APIs and at introspection alike. A token carrying
-- grant_id is never looked up here: its grant already answers.
--
-- The six questions (reference/migrations.md 6): (1) all four engines. (2) jti is pinned
-- case-sensitive and is 64 wide, as refresh_tokens.refresh_token_jti is; the auth server signs a
-- UUID. (3) The lookup compares the jti with =, so the data layer compares the row it got back
-- against the jti it asked for in Go. (4) The jti is the primary key: a token is revoked once, and a
-- second revocation stores nothing. (5) No existing row changes meaning, and nothing is backfilled:
-- before this migration no access token without a grant could be revoked. (6) Each schema.golden
-- gains the table.
--
-- expires_at is the token's own exp. Past it the token is refused for its expiry, so the row has
-- nothing left to refuse: the background worker deletes it then, on that column alone, which the
-- plain index serves.
CREATE TABLE revoked_access_tokens (
    jti TEXT NOT NULL PRIMARY KEY,
    expires_at DATETIME NOT NULL
);
CREATE INDEX idx_revoked_access_tokens_expires_at ON revoked_access_tokens(expires_at);
