-- The header is not recoverable once the column is gone: see the sqlite migration for why.
ALTER TABLE `user_sessions` DROP COLUMN `user_agent`;
