-- The DPoP key a public client's refresh-token family is bound to (#42 decision 11). See the sqlite
-- migration of the same number for what the column holds, who writes it, and why existing rows land
-- NULL with no backfill.
--
-- NVARCHAR(64), the width of the jti columns beside it (a thumbprint is 43 characters), with the
-- collation spelled out: Latin1_General_100_CS_AS_KS_WS_SC_UTF8 is the case-, accent- and
-- width-sensitive collation every string column here carries since 000040. No DEFAULT, so there is
-- no named default constraint, and the down migration drops the column directly, which is safe only
-- because it is nullable.
ALTER TABLE [refresh_tokens] ADD [dpop_jkt] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
