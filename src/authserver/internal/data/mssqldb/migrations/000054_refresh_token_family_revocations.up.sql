-- A revoked refresh token family is recorded, and a child born into one is refused (#132, #259,
-- #437). See the sqlite migration of the same number for why, and for the six questions.
--
-- Both string columns are pinned to the case-sensitive collation per column, as every string
-- column is: the database's own default is whatever an operator pre-created it with, and an
-- unpinned column would compare a jti case-insensitively there (#283).
CREATE TABLE [refresh_token_family_revocations] (
    [first_refresh_token_jti] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL PRIMARY KEY,
    [reason] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [revoked_at] DATETIME2(6) NOT NULL
);
