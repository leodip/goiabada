-- 000002_v0_7.down.sql

-- Reverse modifications to permissions table
ALTER TABLE `permissions`
DROP INDEX `idx_permission_identifier_resource`,
ADD UNIQUE KEY `idx_permission_identifier` (`permission_identifier`);

-- Reverse modifications to users table
ALTER TABLE `users`
DROP COLUMN `phone_number_country_uniqueid`,
DROP COLUMN `phone_number_country_callingcode`;

-- Reverse modifications to user_sessions table
ALTER TABLE `user_sessions`
DROP COLUMN `level2_auth_config_has_changed`;

-- Reverse modifications to settings table
ALTER TABLE `settings`
ADD COLUMN `sms_provider` varchar(32) DEFAULT NULL,
ADD COLUMN `sms_config_encrypted` longblob;
