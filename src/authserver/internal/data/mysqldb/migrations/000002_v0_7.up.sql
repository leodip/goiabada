-- parity: mysql and sqlite only. PostgreSQL and SQL Server were both written after v0.7,
-- so their 000001_initial_create already builds everything this file adds: the
-- idx_permission_identifier_resource unique index, users.phone_number_country_uniqueid and
-- phone_number_country_callingcode, and user_sessions.level2_auth_config_has_changed. Neither
-- of them ever created the settings.sms_provider and sms_config_encrypted columns this file
-- drops, so there is nothing there to drop either.

-- 000002_v0_7.up.sql

-- Modify permissions table
ALTER TABLE `permissions`
DROP INDEX `idx_permission_identifier`,
ADD UNIQUE KEY `idx_permission_identifier_resource` (`permission_identifier`, `resource_id`);

-- Modify users table
ALTER TABLE `users`
ADD COLUMN `phone_number_country_uniqueid` varchar(16) DEFAULT NULL AFTER `phone_number`,
ADD COLUMN `phone_number_country_callingcode` varchar(16) DEFAULT NULL AFTER `phone_number_country_uniqueid`;

-- Modify user_sessions table
ALTER TABLE `user_sessions`
ADD COLUMN `level2_auth_config_has_changed` tinyint(1) NOT NULL AFTER `device_os`;

-- Modify settings table
ALTER TABLE `settings`
DROP COLUMN `sms_provider`,
DROP COLUMN `sms_config_encrypted`;
