-- Reverses migration 000092 (#814). See the sqlite migration for what is lost. SQL Server refuses
-- dropping a column while a default constraint names it, so each goes first.
ALTER TABLE [brands] DROP CONSTRAINT [df_brands_footer_links];
ALTER TABLE [brands] DROP COLUMN [footer_links];
ALTER TABLE [brands] DROP CONSTRAINT [df_brands_support_phone];
ALTER TABLE [brands] DROP COLUMN [support_phone];
ALTER TABLE [brands] DROP CONSTRAINT [df_brands_support_url];
ALTER TABLE [brands] DROP COLUMN [support_url];
ALTER TABLE [brands] DROP CONSTRAINT [df_brands_support_email];
ALTER TABLE [brands] DROP COLUMN [support_email];
