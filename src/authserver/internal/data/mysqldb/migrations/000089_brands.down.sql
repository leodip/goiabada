-- Reverses migration 000089 (#810). See the sqlite migration for what is lost. The foreign key goes
-- before its index, which MySQL refuses to drop while the key uses it.
UPDATE `settings` SET `ui_theme` = (
    SELECT CASE `brands`.`appearance` WHEN 'light' THEN 'light' WHEN 'dark' THEN 'dark' ELSE '' END
    FROM `brands` WHERE `brands`.`id` = `settings`.`default_brand_id`
) WHERE `default_brand_id` IS NOT NULL;

ALTER TABLE `settings` DROP FOREIGN KEY `fk_settings_default_brand`;
DROP INDEX `idx_settings_default_brand_id` ON `settings`;
ALTER TABLE `settings` DROP COLUMN `default_brand_id`;
DROP TABLE `brands`;
