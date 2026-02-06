-- Revert datetime2 precision back to DATETIME2(7) (bare DATETIME2 default)

ALTER TABLE [dbo].[user_profile_pictures] ALTER COLUMN [created_at] DATETIME2 NULL;
ALTER TABLE [dbo].[user_profile_pictures] ALTER COLUMN [updated_at] DATETIME2 NULL;

ALTER TABLE [dbo].[client_logos] ALTER COLUMN [created_at] DATETIME2 NULL;
ALTER TABLE [dbo].[client_logos] ALTER COLUMN [updated_at] DATETIME2 NULL;
