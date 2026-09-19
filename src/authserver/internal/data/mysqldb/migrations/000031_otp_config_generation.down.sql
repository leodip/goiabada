-- Which sessions were flagged is not restored: see the sqlite migration for why.
--
-- The DEFAULT is added and then dropped. 000002 declares this column NOT NULL with no default,
-- and MySQL will not add a NOT NULL column to a populated table without one, so the two
-- statements together are what restores the column 000002 built rather than one that merely
-- looks like it (#268 decision 12).
ALTER TABLE `user_sessions` ADD COLUMN `level2_auth_config_has_changed` tinyint(1) NOT NULL DEFAULT 0;
ALTER TABLE `user_sessions` ALTER COLUMN `level2_auth_config_has_changed` DROP DEFAULT;

ALTER TABLE `user_sessions` DROP COLUMN `otp_config_generation`;
ALTER TABLE `users` DROP COLUMN `otp_config_generation`;
