-- The header is not recoverable once the column is gone, so a database rolled back and migrated
-- forward again reads '' on every row, exactly as a pre-upgrade row does.
ALTER TABLE user_sessions DROP COLUMN user_agent;
