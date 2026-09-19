-- Make PKCE columns nullable to support optional PKCE
-- When PKCE is not required and not provided, these will be NULL
ALTER TABLE codes
ALTER COLUMN code_challenge DROP NOT NULL,
ALTER COLUMN code_challenge_method DROP NOT NULL;
