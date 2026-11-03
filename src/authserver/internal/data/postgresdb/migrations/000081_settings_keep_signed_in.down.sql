-- Migration 000081 down: drop the column. See the sqlite migration for what a database migrated
-- forward again reads.
ALTER TABLE settings DROP COLUMN keep_signed_in;
