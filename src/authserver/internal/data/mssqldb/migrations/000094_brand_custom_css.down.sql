-- Reverses migration 000094 (#816). See the sqlite migration for what is lost. SQL Server refuses
-- dropping a column while a default constraint names it, so the constraint goes first.
ALTER TABLE [brands] DROP CONSTRAINT [df_brands_custom_css];
ALTER TABLE [brands] DROP COLUMN [custom_css];
