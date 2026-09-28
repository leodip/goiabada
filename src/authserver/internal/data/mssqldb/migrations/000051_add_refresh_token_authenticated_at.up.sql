-- When the user behind an ROPC grant authenticated, recorded on its refresh tokens (#125). See the
-- sqlite migration of the same number for what the column is for, who writes it, and why existing
-- rows land NULL with no backfill.
--
-- DATETIME2(6), the type issued_at, expires_at and max_lifetime already have on this table and
-- codes.authenticated_at has on its own. No DEFAULT, so there is no named default constraint here
-- and the down migration drops the column directly, which is safe only because it is nullable.
ALTER TABLE [refresh_tokens] ADD [authenticated_at] DATETIME2(6) NULL;
