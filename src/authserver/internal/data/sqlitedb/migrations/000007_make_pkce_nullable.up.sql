-- SQLite doesn't support ALTER COLUMN to change NULL constraints directly
-- This migration is a no-op for SQLite; the constraint is actually dropped by 000039,
-- which rebuilds the codes table (SQLite enforces NOT NULL on every column type, so
-- leaving it here left codes.code_challenge NOT NULL on this engine alone until then)

SELECT 1;
