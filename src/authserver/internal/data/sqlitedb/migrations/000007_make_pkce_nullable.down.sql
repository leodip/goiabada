-- SQLite doesn't support ALTER COLUMN to change NULL constraints directly
-- This migration is a no-op for SQLite but included for consistency
SELECT 1;
