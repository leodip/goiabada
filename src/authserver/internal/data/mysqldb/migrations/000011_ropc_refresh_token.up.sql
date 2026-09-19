-- Add user_id and client_id columns to refresh_tokens for ROPC flow
-- These allow refresh tokens to be created without a Code entity

-- Add new columns
ALTER TABLE `refresh_tokens` ADD COLUMN `user_id` bigint unsigned NULL;
ALTER TABLE `refresh_tokens` ADD COLUMN `client_id` bigint unsigned NULL;

-- Make code_id nullable (need to drop FK first, then recreate)
ALTER TABLE `refresh_tokens` DROP FOREIGN KEY `fk_refresh_tokens_code`;
ALTER TABLE `refresh_tokens` MODIFY COLUMN `code_id` bigint unsigned NULL;
ALTER TABLE `refresh_tokens` ADD CONSTRAINT `fk_refresh_tokens_code`
    FOREIGN KEY (`code_id`) REFERENCES `codes` (`id`) ON DELETE CASCADE;

-- Add foreign key constraints for new columns
ALTER TABLE `refresh_tokens` ADD CONSTRAINT `fk_refresh_tokens_user`
    FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
ALTER TABLE `refresh_tokens` ADD CONSTRAINT `fk_refresh_tokens_client`
    FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`) ON DELETE CASCADE;

-- Add indexes for the new foreign keys
CREATE INDEX `idx_refresh_tokens_user_id` ON `refresh_tokens` (`user_id`);
CREATE INDEX `idx_refresh_tokens_client_id` ON `refresh_tokens` (`client_id`);
