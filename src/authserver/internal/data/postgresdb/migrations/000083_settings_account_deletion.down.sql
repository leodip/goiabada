-- Migration 000083 down: drop the column. See the sqlite migration for what a database migrated
-- forward again reads.
ALTER TABLE settings DROP COLUMN account_deletion_enabled;
