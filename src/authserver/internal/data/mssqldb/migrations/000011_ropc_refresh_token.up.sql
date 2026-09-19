-- Add user_id and client_id columns to refresh_tokens for ROPC flow
-- These allow refresh tokens to be created without a Code entity

-- Add new columns
ALTER TABLE [refresh_tokens] ADD [user_id] BIGINT NULL;
ALTER TABLE [refresh_tokens] ADD [client_id] BIGINT NULL;

-- Make code_id nullable (need to drop FK first if exists, then recreate)
-- Drop the existing foreign key constraint if it exists
IF EXISTS (SELECT * FROM sys.foreign_keys WHERE name = 'fk_refresh_tokens_code')
BEGIN
    ALTER TABLE [refresh_tokens] DROP CONSTRAINT [fk_refresh_tokens_code];
END;

-- Alter column to be nullable
ALTER TABLE [refresh_tokens] ALTER COLUMN [code_id] BIGINT NULL;

-- Recreate the foreign key constraint
ALTER TABLE [refresh_tokens] ADD CONSTRAINT [fk_refresh_tokens_code]
    FOREIGN KEY ([code_id]) REFERENCES [codes] ([id]) ON DELETE CASCADE;

-- Add foreign key constraints for new columns
ALTER TABLE [refresh_tokens] ADD CONSTRAINT [fk_refresh_tokens_user]
    FOREIGN KEY ([user_id]) REFERENCES [users] ([id]) ON DELETE NO ACTION;

ALTER TABLE [refresh_tokens] ADD CONSTRAINT [fk_refresh_tokens_client]
    FOREIGN KEY ([client_id]) REFERENCES [clients] ([id]) ON DELETE NO ACTION;

-- Add indexes for the new foreign keys
CREATE INDEX [idx_refresh_tokens_user_id] ON [refresh_tokens] ([user_id]);
CREATE INDEX [idx_refresh_tokens_client_id] ON [refresh_tokens] ([client_id]);
