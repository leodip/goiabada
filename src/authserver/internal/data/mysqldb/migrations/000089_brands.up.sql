-- Brands (#810 decisions 1, 2 and 5). See the sqlite migration of the same number for why and for
-- the six questions.
--
-- The table is pinned to the case- and accent-sensitive collation every table here carries (#283).
-- name is as wide as the API's bound. The pointer's index is named, so InnoDB uses it for the
-- foreign key and creates none of its own.
--
-- The stored theme is compared as bytes, as 000065 compares it: utf8mb4_0900_as_cs ignores a soft
-- hyphen, and a binary string is never padded, so only light and dark themselves map to themselves.
CREATE TABLE `brands` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT,
    `created_at` datetime(6) DEFAULT NULL,
    `updated_at` datetime(6) DEFAULT NULL,
    `name` varchar(60) NOT NULL,
    `appearance` varchar(10) NOT NULL,
    `theme` varchar(32) NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_brands_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;

ALTER TABLE `settings` ADD COLUMN `default_brand_id` bigint unsigned NULL;
CREATE INDEX `idx_settings_default_brand_id` ON `settings`(`default_brand_id`);
ALTER TABLE `settings` ADD CONSTRAINT `fk_settings_default_brand`
    FOREIGN KEY (`default_brand_id`) REFERENCES `brands` (`id`);

INSERT INTO `brands` (`created_at`, `updated_at`, `name`, `appearance`, `theme`)
SELECT UTC_TIMESTAMP(6), UTC_TIMESTAMP(6), 'Default',
    CASE
        WHEN CAST(`ui_theme` AS BINARY) = 'light' THEN 'light'
        WHEN CAST(`ui_theme` AS BINARY) = 'dark' THEN 'dark'
        ELSE 'auto'
    END,
    'blueberry'
FROM `settings` WHERE `id` = 1;

UPDATE `settings` SET `default_brand_id` = (SELECT `id` FROM `brands` WHERE `name` = 'Default') WHERE `id` = 1;
