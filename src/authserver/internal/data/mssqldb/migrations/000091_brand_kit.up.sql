-- The brand kit (#813 decision 2). See the sqlite migration of the same number for why and for the
-- six questions.
--
-- Every string column is pinned to the case-sensitive collation per column, as every string column
-- is (#283). content is VARBINARY(MAX), as a client logo's is.
--
-- The default constraints are NAMED for the reason 000031 gives: SQL Server refuses to drop a
-- column while a default constraint depends on it, so the down migration drops each constraint by
-- name first. The foreign keys are named for the same reason.
CREATE TABLE [brand_assets] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] DATETIME2(6) NOT NULL,
    [kind] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [content_type] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [fingerprint] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [width] INT NOT NULL,
    [height] INT NOT NULL,
    [content] VARBINARY(MAX) NOT NULL
);
CREATE INDEX [idx_brand_assets_created_at] ON [brand_assets]([created_at]);

ALTER TABLE [brands] ADD [corners] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_brands_corners] DEFAULT 'rounded';
ALTER TABLE [brands] ADD [font] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_brands_font] DEFAULT 'system-ui';
ALTER TABLE [brands] ADD [background_fit] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_brands_background_fit] DEFAULT 'cover';
ALTER TABLE [brands] ADD [hide_app_name] BIT NOT NULL
    CONSTRAINT [df_brands_hide_app_name] DEFAULT 0;

ALTER TABLE [brands] ADD [logo_asset_id] BIGINT NULL
    CONSTRAINT [fk_brands_logo_asset] FOREIGN KEY REFERENCES [brand_assets] ([id]);
ALTER TABLE [brands] ADD [dark_logo_asset_id] BIGINT NULL
    CONSTRAINT [fk_brands_dark_logo_asset] FOREIGN KEY REFERENCES [brand_assets] ([id]);
ALTER TABLE [brands] ADD [favicon_asset_id] BIGINT NULL
    CONSTRAINT [fk_brands_favicon_asset] FOREIGN KEY REFERENCES [brand_assets] ([id]);
ALTER TABLE [brands] ADD [background_asset_id] BIGINT NULL
    CONSTRAINT [fk_brands_background_asset] FOREIGN KEY REFERENCES [brand_assets] ([id]);
ALTER TABLE [brands] ADD [regular_font_asset_id] BIGINT NULL
    CONSTRAINT [fk_brands_regular_font_asset] FOREIGN KEY REFERENCES [brand_assets] ([id]);
ALTER TABLE [brands] ADD [bold_font_asset_id] BIGINT NULL
    CONSTRAINT [fk_brands_bold_font_asset] FOREIGN KEY REFERENCES [brand_assets] ([id]);

CREATE INDEX [idx_brands_logo_asset_id] ON [brands]([logo_asset_id]);
CREATE INDEX [idx_brands_dark_logo_asset_id] ON [brands]([dark_logo_asset_id]);
CREATE INDEX [idx_brands_favicon_asset_id] ON [brands]([favicon_asset_id]);
CREATE INDEX [idx_brands_background_asset_id] ON [brands]([background_asset_id]);
CREATE INDEX [idx_brands_regular_font_asset_id] ON [brands]([regular_font_asset_id]);
CREATE INDEX [idx_brands_bold_font_asset_id] ON [brands]([bold_font_asset_id]);
