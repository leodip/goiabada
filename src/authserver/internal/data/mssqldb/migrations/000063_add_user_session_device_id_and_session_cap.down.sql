-- Migration 000063 down: drop both columns. See the sqlite migration for what a database migrated
-- forward again reads. Constraint before column: see the up migration for why.
ALTER TABLE [user_sessions] DROP CONSTRAINT [df_user_sessions_device_id];
ALTER TABLE [user_sessions] DROP COLUMN [device_id];

ALTER TABLE [settings] DROP CONSTRAINT [df_settings_max_user_sessions_per_user];
ALTER TABLE [settings] DROP COLUMN [max_user_sessions_per_user];
