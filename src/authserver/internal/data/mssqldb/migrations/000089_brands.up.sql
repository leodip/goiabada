-- Brands (#810 decisions 1, 2 and 5). See the sqlite migration of the same number for why and for
-- the six questions.
--
-- Every string column is pinned to the case-sensitive collation per column, as every string column
-- is: the database's own default is whatever an operator pre-created it with (#283). name is as wide
-- as the API's bound, which counts UTF-16 code units as NVARCHAR does.
--
-- The stored theme is compared exactly, as 000065 compares it: a binary collation, so case and
-- ignorable characters count, and a '|' after each side, since SQL Server pads the shorter string
-- with spaces before comparing.
CREATE TABLE [brands] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] DATETIME2(6) NULL,
    [updated_at] DATETIME2(6) NULL,
    [name] NVARCHAR(60) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [appearance] NVARCHAR(10) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [theme] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
);
CREATE UNIQUE INDEX [idx_brands_name] ON [brands]([name]);

ALTER TABLE [settings] ADD [default_brand_id] BIGINT NULL
    CONSTRAINT [fk_settings_default_brand] FOREIGN KEY REFERENCES [brands] ([id]);
CREATE INDEX [idx_settings_default_brand_id] ON [settings]([default_brand_id]);

INSERT INTO [brands] ([created_at], [updated_at], [name], [appearance], [theme])
SELECT SYSUTCDATETIME(), SYSUTCDATETIME(), N'Default',
    CASE
        WHEN [ui_theme] COLLATE Latin1_General_100_BIN2 + N'|' = N'light|' THEN N'light'
        WHEN [ui_theme] COLLATE Latin1_General_100_BIN2 + N'|' = N'dark|' THEN N'dark'
        ELSE N'auto'
    END,
    N'blueberry'
FROM [settings] WHERE [id] = 1;

-- Inside EXEC because SQL Server compiles the whole batch before running any of it, so a statement
-- naming the column just added fails with "Invalid column name": see 000029.
EXEC('UPDATE [settings] SET [default_brand_id] = (SELECT [id] FROM [brands] WHERE [name] = N''Default'') WHERE [id] = 1');
