-- When the user behind an ROPC grant authenticated, recorded on its refresh tokens (#125). See the
-- sqlite migration of the same number for what the column is for, who writes it, and why existing
-- rows land NULL with no backfill.
--
-- timestamp(6) without time zone, the type issued_at, expires_at and max_lifetime already have on
-- this table and codes.authenticated_at has on its own.
ALTER TABLE refresh_tokens ADD COLUMN authenticated_at timestamp(6) without time zone;
