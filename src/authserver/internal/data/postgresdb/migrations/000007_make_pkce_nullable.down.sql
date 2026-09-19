-- Revert PKCE columns to NOT NULL
-- Note: This may fail if there are NULL values in the table
ALTER TABLE codes
ALTER COLUMN code_challenge SET NOT NULL,
ALTER COLUMN code_challenge_method SET NOT NULL;
