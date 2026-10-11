-- A session's device identifier and the per-user session cap (#564 decision 11). See the sqlite
-- migration of the same number for what the two columns hold, and why each carries a default rather
-- than a backfill.
--
-- NVARCHAR and the collation spelled out, as every string column on this table is (#283). 64
-- characters is a SHA-256 in hex.
--
-- The default constraints are NAMED for the reason 000031 gives: SQL Server refuses to drop a column
-- while a default constraint depends on it, so the down migration drops each constraint by name first.
ALTER TABLE [user_sessions] ADD [device_id] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_user_sessions_device_id] DEFAULT '';

ALTER TABLE [settings] ADD [max_user_sessions_per_user] INT NOT NULL
    CONSTRAINT [df_settings_max_user_sessions_per_user] DEFAULT 20;
