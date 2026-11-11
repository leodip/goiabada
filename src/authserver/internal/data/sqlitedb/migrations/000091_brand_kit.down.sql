-- Reverses migration 000091 (#813): drops every brand's kit and every stored asset. Each index goes
-- before its column, which SQLite requires before DROP COLUMN, and the slots before the table they
-- reference.
DROP INDEX idx_brands_bold_font_asset_id;
DROP INDEX idx_brands_regular_font_asset_id;
DROP INDEX idx_brands_background_asset_id;
DROP INDEX idx_brands_favicon_asset_id;
DROP INDEX idx_brands_dark_logo_asset_id;
DROP INDEX idx_brands_logo_asset_id;

ALTER TABLE brands DROP COLUMN bold_font_asset_id;
ALTER TABLE brands DROP COLUMN regular_font_asset_id;
ALTER TABLE brands DROP COLUMN background_asset_id;
ALTER TABLE brands DROP COLUMN favicon_asset_id;
ALTER TABLE brands DROP COLUMN dark_logo_asset_id;
ALTER TABLE brands DROP COLUMN logo_asset_id;

ALTER TABLE brands DROP COLUMN hide_app_name;
ALTER TABLE brands DROP COLUMN background_fit;
ALTER TABLE brands DROP COLUMN font;
ALTER TABLE brands DROP COLUMN corners;

DROP INDEX idx_brand_assets_created_at;
DROP TABLE brand_assets;
