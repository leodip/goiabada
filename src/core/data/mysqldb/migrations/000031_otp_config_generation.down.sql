-- Which sessions were flagged is not restored: see the sqlite migration for why. The column comes
-- back with a default the original did not have, because existing rows need a value.
ALTER TABLE `user_sessions` ADD COLUMN `level2_auth_config_has_changed` tinyint(1) NOT NULL DEFAULT 0;

ALTER TABLE `user_sessions` DROP COLUMN `otp_config_generation`;
ALTER TABLE `users` DROP COLUMN `otp_config_generation`;
