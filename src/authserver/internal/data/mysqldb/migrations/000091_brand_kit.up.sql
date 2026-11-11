-- The brand kit (#813 decision 2). See the sqlite migration of the same number for why and for the
-- six questions.
--
-- brand_assets is pinned to the case- and accent-sensitive collation every table here carries
-- (#283); the columns added to brands inherit that table's. content is a LONGBLOB, as a client
-- logo's is. Each slot's index is named and created before its key, so InnoDB uses it for the
-- foreign key and creates none of its own.
CREATE TABLE `brand_assets` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT,
    `created_at` datetime(6) NOT NULL,
    `kind` varchar(16) NOT NULL,
    `content_type` varchar(64) NOT NULL,
    `fingerprint` varchar(64) NOT NULL,
    `width` int NOT NULL,
    `height` int NOT NULL,
    `content` longblob NOT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_brand_assets_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;

ALTER TABLE `brands` ADD COLUMN `corners` varchar(16) NOT NULL DEFAULT 'rounded';
ALTER TABLE `brands` ADD COLUMN `font` varchar(16) NOT NULL DEFAULT 'system-ui';
ALTER TABLE `brands` ADD COLUMN `background_fit` varchar(16) NOT NULL DEFAULT 'cover';
ALTER TABLE `brands` ADD COLUMN `hide_app_name` tinyint(1) NOT NULL DEFAULT 0;

ALTER TABLE `brands` ADD COLUMN `logo_asset_id` bigint unsigned NULL;
ALTER TABLE `brands` ADD COLUMN `dark_logo_asset_id` bigint unsigned NULL;
ALTER TABLE `brands` ADD COLUMN `favicon_asset_id` bigint unsigned NULL;
ALTER TABLE `brands` ADD COLUMN `background_asset_id` bigint unsigned NULL;
ALTER TABLE `brands` ADD COLUMN `regular_font_asset_id` bigint unsigned NULL;
ALTER TABLE `brands` ADD COLUMN `bold_font_asset_id` bigint unsigned NULL;

CREATE INDEX `idx_brands_logo_asset_id` ON `brands`(`logo_asset_id`);
CREATE INDEX `idx_brands_dark_logo_asset_id` ON `brands`(`dark_logo_asset_id`);
CREATE INDEX `idx_brands_favicon_asset_id` ON `brands`(`favicon_asset_id`);
CREATE INDEX `idx_brands_background_asset_id` ON `brands`(`background_asset_id`);
CREATE INDEX `idx_brands_regular_font_asset_id` ON `brands`(`regular_font_asset_id`);
CREATE INDEX `idx_brands_bold_font_asset_id` ON `brands`(`bold_font_asset_id`);

ALTER TABLE `brands` ADD CONSTRAINT `fk_brands_logo_asset`
    FOREIGN KEY (`logo_asset_id`) REFERENCES `brand_assets` (`id`);
ALTER TABLE `brands` ADD CONSTRAINT `fk_brands_dark_logo_asset`
    FOREIGN KEY (`dark_logo_asset_id`) REFERENCES `brand_assets` (`id`);
ALTER TABLE `brands` ADD CONSTRAINT `fk_brands_favicon_asset`
    FOREIGN KEY (`favicon_asset_id`) REFERENCES `brand_assets` (`id`);
ALTER TABLE `brands` ADD CONSTRAINT `fk_brands_background_asset`
    FOREIGN KEY (`background_asset_id`) REFERENCES `brand_assets` (`id`);
ALTER TABLE `brands` ADD CONSTRAINT `fk_brands_regular_font_asset`
    FOREIGN KEY (`regular_font_asset_id`) REFERENCES `brand_assets` (`id`);
ALTER TABLE `brands` ADD CONSTRAINT `fk_brands_bold_font_asset`
    FOREIGN KEY (`bold_font_asset_id`) REFERENCES `brand_assets` (`id`);
