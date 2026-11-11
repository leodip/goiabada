-- Reverses migration 000091 (#813). See the sqlite migration for what is lost. Each foreign key goes
-- before its index, which MySQL refuses to drop while the key uses it.
ALTER TABLE `brands` DROP FOREIGN KEY `fk_brands_bold_font_asset`;
ALTER TABLE `brands` DROP FOREIGN KEY `fk_brands_regular_font_asset`;
ALTER TABLE `brands` DROP FOREIGN KEY `fk_brands_background_asset`;
ALTER TABLE `brands` DROP FOREIGN KEY `fk_brands_favicon_asset`;
ALTER TABLE `brands` DROP FOREIGN KEY `fk_brands_dark_logo_asset`;
ALTER TABLE `brands` DROP FOREIGN KEY `fk_brands_logo_asset`;

DROP INDEX `idx_brands_bold_font_asset_id` ON `brands`;
DROP INDEX `idx_brands_regular_font_asset_id` ON `brands`;
DROP INDEX `idx_brands_background_asset_id` ON `brands`;
DROP INDEX `idx_brands_favicon_asset_id` ON `brands`;
DROP INDEX `idx_brands_dark_logo_asset_id` ON `brands`;
DROP INDEX `idx_brands_logo_asset_id` ON `brands`;

ALTER TABLE `brands` DROP COLUMN `bold_font_asset_id`;
ALTER TABLE `brands` DROP COLUMN `regular_font_asset_id`;
ALTER TABLE `brands` DROP COLUMN `background_asset_id`;
ALTER TABLE `brands` DROP COLUMN `favicon_asset_id`;
ALTER TABLE `brands` DROP COLUMN `dark_logo_asset_id`;
ALTER TABLE `brands` DROP COLUMN `logo_asset_id`;

ALTER TABLE `brands` DROP COLUMN `hide_app_name`;
ALTER TABLE `brands` DROP COLUMN `background_fit`;
ALTER TABLE `brands` DROP COLUMN `font`;
ALTER TABLE `brands` DROP COLUMN `corners`;

DROP TABLE `brand_assets`;
