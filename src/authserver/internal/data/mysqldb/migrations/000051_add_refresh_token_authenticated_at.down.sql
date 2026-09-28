-- See the sqlite migration of the same number for what an ROPC refresh writes once this is gone.
ALTER TABLE `refresh_tokens` DROP COLUMN `authenticated_at`;
