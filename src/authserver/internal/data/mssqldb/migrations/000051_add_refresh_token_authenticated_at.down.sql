-- See the sqlite migration of the same number for what an ROPC refresh writes once this is gone.
-- No constraint to drop first, because the up migration gave the column no default.
ALTER TABLE [refresh_tokens] DROP COLUMN [authenticated_at];
