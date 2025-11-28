-- Revert: Remove user_id and client_id columns, make code_id NOT NULL again

-- First delete any ROPC tokens (those with NULL code_id)
DELETE FROM `refresh_tokens` WHERE `code_id` IS NULL;

-- Drop indexes
DROP INDEX `idx_refresh_tokens_user_id` ON `refresh_tokens`;
DROP INDEX `idx_refresh_tokens_client_id` ON `refresh_tokens`;

-- Drop foreign key constraints for new columns
ALTER TABLE `refresh_tokens` DROP FOREIGN KEY `fk_refresh_tokens_user`;
ALTER TABLE `refresh_tokens` DROP FOREIGN KEY `fk_refresh_tokens_client`;

-- Make code_id NOT NULL again (need to drop FK first, then recreate)
ALTER TABLE `refresh_tokens` DROP FOREIGN KEY `fk_refresh_tokens_code`;
ALTER TABLE `refresh_tokens` MODIFY COLUMN `code_id` bigint unsigned NOT NULL;
ALTER TABLE `refresh_tokens` ADD CONSTRAINT `fk_refresh_tokens_code`
    FOREIGN KEY (`code_id`) REFERENCES `codes` (`id`) ON DELETE CASCADE;

-- Drop columns
ALTER TABLE `refresh_tokens` DROP COLUMN `user_id`;
ALTER TABLE `refresh_tokens` DROP COLUMN `client_id`;
