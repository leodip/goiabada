-- Revert: Remove user_id and client_id columns, make code_id NOT NULL again

-- First delete any ROPC tokens (those with NULL code_id)
DELETE FROM `refresh_tokens` WHERE `code_id` IS NULL;

-- Drop the foreign key constraints BEFORE the indexes they are enforced through. InnoDB
-- requires an index on a foreign key's columns and refuses to drop the last one that covers a
-- live constraint: the other order fails with "Cannot drop index 'idx_refresh_tokens_user_id':
-- needed in a foreign key constraint" and leaves the schema half rolled back. Only MySQL has
-- this rule, which is why the other three engines' 000011 downs read in either order (#268).
ALTER TABLE `refresh_tokens` DROP FOREIGN KEY `fk_refresh_tokens_user`;
ALTER TABLE `refresh_tokens` DROP FOREIGN KEY `fk_refresh_tokens_client`;

-- Drop indexes
DROP INDEX `idx_refresh_tokens_user_id` ON `refresh_tokens`;
DROP INDEX `idx_refresh_tokens_client_id` ON `refresh_tokens`;

-- Make code_id NOT NULL again (need to drop FK first, then recreate)
ALTER TABLE `refresh_tokens` DROP FOREIGN KEY `fk_refresh_tokens_code`;
ALTER TABLE `refresh_tokens` MODIFY COLUMN `code_id` bigint unsigned NOT NULL;
ALTER TABLE `refresh_tokens` ADD CONSTRAINT `fk_refresh_tokens_code`
    FOREIGN KEY (`code_id`) REFERENCES `codes` (`id`) ON DELETE CASCADE;

-- Drop columns
ALTER TABLE `refresh_tokens` DROP COLUMN `user_id`;
ALTER TABLE `refresh_tokens` DROP COLUMN `client_id`;
