-- Migration 000083 down: drop the column. A database migrated forward again reads on, whatever an
-- administrator had chosen.
ALTER TABLE settings DROP COLUMN account_deletion_enabled;
