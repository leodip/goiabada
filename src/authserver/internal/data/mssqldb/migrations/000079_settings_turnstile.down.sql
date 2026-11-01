-- Migration 000079 down: drop the three columns. See the sqlite migration for what a database migrated
-- forward again reads. Constraint before column: see the up migration for why.
ALTER TABLE [settings] DROP COLUMN [turnstile_secret_key_encrypted];

ALTER TABLE [settings] DROP CONSTRAINT [df_settings_turnstile_site_key];
ALTER TABLE [settings] DROP COLUMN [turnstile_site_key];

ALTER TABLE [settings] DROP CONSTRAINT [df_settings_turnstile_enabled];
ALTER TABLE [settings] DROP COLUMN [turnstile_enabled];
