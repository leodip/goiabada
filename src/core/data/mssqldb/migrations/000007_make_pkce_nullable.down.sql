-- Revert PKCE columns to NOT NULL
-- Note: This may fail if there are NULL values in the table
--
-- NVARCHAR, not the VARCHAR the up migration ALTERed these two columns to. 000001 declares them
-- NVARCHAR(256) and NVARCHAR(10), so restoring them as VARCHAR left a database rolled back to
-- 000006 holding non-Unicode columns a fresh install of that release does not have. The up's own
-- downgrade is one of the five divergences #282 found and 000038 converted back; what this file
-- owes is the shape 000006 actually has, which is 000001's (#268 decision 12).
ALTER TABLE [dbo].[codes]
ALTER COLUMN [code_challenge] NVARCHAR(256) NOT NULL;

ALTER TABLE [dbo].[codes]
ALTER COLUMN [code_challenge_method] NVARCHAR(10) NOT NULL;
