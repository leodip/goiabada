-- Reverses migration 000089 (#810). See the sqlite migration for what is lost. SQL Server refuses
-- dropping a column while a constraint or an index names it, so both go first.
UPDATE [settings] SET [ui_theme] = (
    SELECT CASE [brands].[appearance] WHEN N'light' THEN N'light' WHEN N'dark' THEN N'dark' ELSE N'' END
    FROM [brands] WHERE [brands].[id] = [settings].[default_brand_id]
) WHERE [default_brand_id] IS NOT NULL;

ALTER TABLE [settings] DROP CONSTRAINT [fk_settings_default_brand];
DROP INDEX [idx_settings_default_brand_id] ON [settings];
ALTER TABLE [settings] DROP COLUMN [default_brand_id];
DROP TABLE [brands];
