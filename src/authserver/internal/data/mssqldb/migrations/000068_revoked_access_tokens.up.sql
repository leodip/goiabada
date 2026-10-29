-- An access token without a grant is revoked by its jti (#676 decision 1). See the sqlite migration
-- of the same number for why, for the six questions and for what the index serves.
--
-- The jti is pinned to the case-sensitive collation per column, as every string column is: the
-- database's own default is whatever an operator pre-created it with, and an unpinned column would
-- compare a jti case-insensitively there (#283).
CREATE TABLE [revoked_access_tokens] (
    [jti] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL PRIMARY KEY,
    [expires_at] DATETIME2(6) NOT NULL
);
CREATE INDEX [idx_revoked_access_tokens_expires_at] ON [revoked_access_tokens]([expires_at]);
