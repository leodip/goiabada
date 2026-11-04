-- Migration 000081 down: drop the column. A database migrated forward again reads 'ask', whatever an
-- administrator had chosen.
ALTER TABLE settings DROP COLUMN keep_signed_in;
