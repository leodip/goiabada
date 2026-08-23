-- Per-user OTP configuration generation (#242). See the sqlite migration of the same number for what
-- the columns mean, why both clauses of the seed are load-bearing, and why -1 is the seeded value.
--
-- The boolean literal is 1 here rather than true: mysql declares both otp_enabled and
-- level2_auth_config_has_changed tinyint(1), where postgres declares them boolean and takes true.
ALTER TABLE `users` ADD COLUMN `otp_config_generation` bigint NOT NULL DEFAULT 0;
ALTER TABLE `user_sessions` ADD COLUMN `otp_config_generation` bigint NOT NULL DEFAULT 0;

UPDATE `user_sessions` SET `otp_config_generation` = -1
 WHERE `level2_auth_config_has_changed` = 1
    OR `user_id` IN (SELECT `id` FROM `users` WHERE `otp_enabled` = 1);

ALTER TABLE `user_sessions` DROP COLUMN `level2_auth_config_has_changed`;
