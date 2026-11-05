-- The "Let users delete their own account" setting (#783 decision 5). See the sqlite migration of
-- the same number for what the column holds, and why it defaults to on.
--
-- The default constraint is NAMED for the reason 000031 gives: SQL Server refuses to drop a column
-- while a default constraint depends on it, so the down migration drops the constraint by name first.
ALTER TABLE [settings] ADD [account_deletion_enabled] BIT NOT NULL
    CONSTRAINT [df_settings_account_deletion_enabled] DEFAULT 1;
