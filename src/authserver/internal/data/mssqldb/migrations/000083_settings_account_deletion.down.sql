-- Migration 000083 down: drop the column. See the sqlite migration for what a database migrated
-- forward again reads. Constraint before column: see the up migration for why.
ALTER TABLE [settings] DROP CONSTRAINT [df_settings_account_deletion_enabled];
ALTER TABLE [settings] DROP COLUMN [account_deletion_enabled];
