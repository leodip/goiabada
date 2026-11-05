-- The "Let users delete their own account" setting (#783 decision 5). See the sqlite migration of
-- the same number for what the column holds, and why it defaults to on.
ALTER TABLE `settings` ADD COLUMN `account_deletion_enabled` tinyint(1) NOT NULL DEFAULT 1;
