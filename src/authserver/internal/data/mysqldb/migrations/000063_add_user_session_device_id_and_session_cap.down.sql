-- Migration 000063 down: drop both columns. See the sqlite migration for what a database migrated
-- forward again reads.
ALTER TABLE `user_sessions` DROP COLUMN `device_id`;

ALTER TABLE `settings` DROP COLUMN `max_user_sessions_per_user`;
