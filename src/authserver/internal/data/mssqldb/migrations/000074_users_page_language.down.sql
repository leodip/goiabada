-- Reverses migration 000074 (#631). Every user's page language is lost: see the sqlite migration.
--
-- Constraint before column: see the up migration for why.
ALTER TABLE [users] DROP CONSTRAINT [df_users_page_language];
ALTER TABLE [users] DROP COLUMN [page_language];
