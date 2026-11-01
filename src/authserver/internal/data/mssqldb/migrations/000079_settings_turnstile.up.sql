-- The Cloudflare Turnstile challenge's settings (#642 decision 1). See the sqlite migration of the
-- same number for what the three columns hold, and why the switch and the site key carry a default.
--
-- NVARCHAR and the collation spelled out, as every string column on this table is (#283).
--
-- The default constraints are NAMED for the reason 000031 gives: SQL Server refuses to drop a column
-- while a default constraint depends on it, so the down migration drops each constraint by name first.
ALTER TABLE [settings] ADD [turnstile_enabled] BIT NOT NULL
    CONSTRAINT [df_settings_turnstile_enabled] DEFAULT 0;

ALTER TABLE [settings] ADD [turnstile_site_key] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_settings_turnstile_site_key] DEFAULT '';

ALTER TABLE [settings] ADD [turnstile_secret_key_encrypted] VARBINARY(MAX) NULL;
