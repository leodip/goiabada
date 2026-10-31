-- Reverses migration 000074 (#631). Every user's page language is lost: see the sqlite migration.
ALTER TABLE `users` DROP COLUMN `page_language`;
