-- A brand's custom palette (#815 decision 3). See the sqlite migration of the same number for why
-- and for the six questions.
--
-- The column is pinned to the case-sensitive collation per column, as every string column is
-- (#283). It is NVARCHAR(MAX), as footer_links is, and nullable with no default, so it has no
-- default constraint for the down migration to drop first.
ALTER TABLE [brands] ADD [palette] NVARCHAR(MAX) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
