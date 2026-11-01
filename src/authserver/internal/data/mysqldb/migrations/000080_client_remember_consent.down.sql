-- Migration 000080 down: drop clients.remember_consent, with every setting an administrator turned
-- on since.
ALTER TABLE `clients` DROP COLUMN `remember_consent`;
