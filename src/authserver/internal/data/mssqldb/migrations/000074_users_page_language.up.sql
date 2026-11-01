-- The language a user chose for Goiabada's own pages and emails (#631 decision 8). See the sqlite
-- migration of the same number for what the column holds and why existing rows land on ''.
--
-- NVARCHAR and the collation spelled out, as every string column on this table is, so the tag
-- compares case-sensitively here as on the other three engines (#283). 32 wide, as locale is.
--
-- The default constraint is NAMED for the reason 000031 gives: SQL Server refuses to drop a column
-- while a default constraint depends on it, so the down migration drops the constraint by name first.
ALTER TABLE [users] ADD [page_language] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_users_page_language] DEFAULT '';
