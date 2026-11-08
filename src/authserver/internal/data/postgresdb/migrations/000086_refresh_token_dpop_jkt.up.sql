-- The DPoP key a public client's refresh-token family is bound to (#42 decision 11). See the sqlite
-- migration of the same number for what the column holds, who writes it, and why existing rows land
-- NULL with no backfill.
--
-- character varying(64), the width of the jti columns beside it; a thumbprint is 43 characters.
-- PostgreSQL compares strings byte-wise, so the column needs no collation pin.
ALTER TABLE refresh_tokens ADD COLUMN dpop_jkt character varying(64);
