-- Per-user authentication generation boundary (#106). See the sqlite migration of
-- the same number for what the columns mean and why existing rows land at 0.
ALTER TABLE `users` ADD COLUMN `auth_state_generation` bigint NOT NULL DEFAULT 0;
ALTER TABLE `user_sessions` ADD COLUMN `auth_state_generation` bigint NOT NULL DEFAULT 0;
ALTER TABLE `codes` ADD COLUMN `auth_state_generation` bigint NOT NULL DEFAULT 0;
ALTER TABLE `refresh_tokens` ADD COLUMN `auth_state_generation` bigint NOT NULL DEFAULT 0;

-- Only one index is missing here. InnoDB indexes foreign key columns automatically,
-- and the initial migration declares KEY fk_codes_user, KEY fk_refresh_tokens_code
-- and KEY fk_user_sessions_user inline, while 000011 added idx_refresh_tokens_user_id.
-- codes.session_identifier has no foreign key, so nothing covers it.
CREATE INDEX `idx_codes_session_identifier` ON `codes`(`session_identifier`);
