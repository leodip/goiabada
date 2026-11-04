-- The "Keep users signed in after the browser closes" setting (#743 decisions 3 and 4). See the
-- sqlite migration of the same number for what the column holds, and why it defaults to 'ask'.
--
-- NVARCHAR and the collation spelled out, as every string column on this table is (#283). The width
-- is the SMTP encryption's, the row's other lower-case enumeration.
--
-- The default constraint is NAMED for the reason 000031 gives: SQL Server refuses to drop a column
-- while a default constraint depends on it, so the down migration drops the constraint by name first.
ALTER TABLE [settings] ADD [keep_signed_in] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_settings_keep_signed_in] DEFAULT 'ask';
