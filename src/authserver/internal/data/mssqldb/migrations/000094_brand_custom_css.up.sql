-- A brand's custom CSS (#816 decision 4). See the sqlite migration of the same number for why and
-- for the six questions.
--
-- The column is pinned to the case-sensitive collation per column, as every string column is
-- (#283). It is NVARCHAR(MAX), as footer_links is. The default constraint is NAMED for the reason
-- 000031 gives: SQL Server refuses to drop a column while a default constraint depends on it, so
-- the down migration drops the constraint by name first.
ALTER TABLE [brands] ADD [custom_css] NVARCHAR(MAX) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_brands_custom_css] DEFAULT '';
