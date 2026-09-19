DROP INDEX `idx_codes_session_identifier` ON `codes`;

ALTER TABLE `refresh_tokens` DROP COLUMN `auth_state_generation`;
ALTER TABLE `codes` DROP COLUMN `auth_state_generation`;
ALTER TABLE `user_sessions` DROP COLUMN `auth_state_generation`;
ALTER TABLE `users` DROP COLUMN `auth_state_generation`;
