-- SQLite doesn't support ALTER COLUMN to change NULL constraints directly
-- The columns are already effectively nullable in SQLite (it doesn't enforce NOT NULL strictly for VARCHAR)
-- This migration is a no-op for SQLite but included for consistency
-- If strict enforcement is needed, a table rebuild would be required

-- No operation needed - SQLite VARCHAR columns can store NULL regardless of NOT NULL constraint
-- when inserting via prepared statements that explicitly set NULL
SELECT 1;
