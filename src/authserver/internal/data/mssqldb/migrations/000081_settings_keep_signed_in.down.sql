-- Migration 000081 down: drop the column. See the sqlite migration for what a database migrated
-- forward again reads. Constraint before column: see the up migration for why.
ALTER TABLE [settings] DROP CONSTRAINT [df_settings_keep_signed_in];
ALTER TABLE [settings] DROP COLUMN [keep_signed_in];
