-- Revert: Remove user_id and client_id columns, make code_id NOT NULL again

-- First delete any ROPC tokens (those with NULL code_id)
DELETE FROM [refresh_tokens] WHERE [code_id] IS NULL;

-- Drop indexes
DROP INDEX IF EXISTS [idx_refresh_tokens_user_id] ON [refresh_tokens];
DROP INDEX IF EXISTS [idx_refresh_tokens_client_id] ON [refresh_tokens];

-- Drop foreign key constraints for new columns
IF EXISTS (SELECT * FROM sys.foreign_keys WHERE name = 'fk_refresh_tokens_user')
BEGIN
    ALTER TABLE [refresh_tokens] DROP CONSTRAINT [fk_refresh_tokens_user];
END;

IF EXISTS (SELECT * FROM sys.foreign_keys WHERE name = 'fk_refresh_tokens_client')
BEGIN
    ALTER TABLE [refresh_tokens] DROP CONSTRAINT [fk_refresh_tokens_client];
END;

-- Make code_id NOT NULL again
IF EXISTS (SELECT * FROM sys.foreign_keys WHERE name = 'fk_refresh_tokens_code')
BEGIN
    ALTER TABLE [refresh_tokens] DROP CONSTRAINT [fk_refresh_tokens_code];
END;

ALTER TABLE [refresh_tokens] ALTER COLUMN [code_id] BIGINT NOT NULL;

ALTER TABLE [refresh_tokens] ADD CONSTRAINT [fk_refresh_tokens_code]
    FOREIGN KEY ([code_id]) REFERENCES [codes] ([id]) ON DELETE CASCADE;

-- Drop columns
ALTER TABLE [refresh_tokens] DROP COLUMN [user_id];
ALTER TABLE [refresh_tokens] DROP COLUMN [client_id];
