-- The DPoP key an authorization code is bound to (#42 decision 14). See the sqlite migration of the
-- same number for what the column holds, who writes it, and why existing rows land NULL with no
-- backfill.
--
-- character varying(64), the width of refresh_tokens.dpop_jkt; a thumbprint is 43 characters.
-- PostgreSQL compares strings byte-wise, so the column needs no collation pin.
ALTER TABLE codes ADD COLUMN dpop_jkt character varying(64);
