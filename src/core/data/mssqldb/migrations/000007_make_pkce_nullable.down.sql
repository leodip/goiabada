-- Revert PKCE columns to NOT NULL
-- Note: This may fail if there are NULL values in the table
ALTER TABLE [dbo].[codes]
ALTER COLUMN [code_challenge] VARCHAR(256) NOT NULL;

ALTER TABLE [dbo].[codes]
ALTER COLUMN [code_challenge_method] VARCHAR(10) NOT NULL;
