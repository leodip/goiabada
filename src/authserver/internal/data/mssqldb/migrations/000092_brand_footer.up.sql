-- A brand's support contact and footer links (#814 decision 8). See the sqlite migration of the
-- same number for why and for the six questions.
--
-- Every string column is pinned to the case-sensitive collation per column, as every string column
-- is (#283). footer_links is NVARCHAR(MAX), as audit_logs.details is. The default constraints are
-- NAMED for the reason 000031 gives: SQL Server refuses to drop a column while a default
-- constraint depends on it, so the down migration drops each constraint by name first.
ALTER TABLE [brands] ADD [support_email] NVARCHAR(254) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_brands_support_email] DEFAULT '';
ALTER TABLE [brands] ADD [support_url] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_brands_support_url] DEFAULT '';
ALTER TABLE [brands] ADD [support_phone] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_brands_support_phone] DEFAULT '';
ALTER TABLE [brands] ADD [footer_links] NVARCHAR(MAX) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_brands_footer_links] DEFAULT '[]';
