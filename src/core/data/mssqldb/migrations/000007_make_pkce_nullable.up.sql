-- Make PKCE columns nullable to support optional PKCE
-- When PKCE is not required and not provided, these will be NULL
ALTER TABLE [dbo].[codes]
ALTER COLUMN [code_challenge] VARCHAR(256) NULL;

ALTER TABLE [dbo].[codes]
ALTER COLUMN [code_challenge_method] VARCHAR(10) NULL;
