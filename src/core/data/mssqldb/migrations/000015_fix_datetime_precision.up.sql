-- Fix datetime2 precision on user_profile_pictures and client_logos tables
-- Migrations 000008 and 000014 used bare DATETIME2 (defaults to precision 7),
-- while all other tables use DATETIME2(6). Standardize to DATETIME2(6).

ALTER TABLE [dbo].[user_profile_pictures] ALTER COLUMN [created_at] DATETIME2(6) NULL;
ALTER TABLE [dbo].[user_profile_pictures] ALTER COLUMN [updated_at] DATETIME2(6) NULL;

ALTER TABLE [dbo].[client_logos] ALTER COLUMN [created_at] DATETIME2(6) NULL;
ALTER TABLE [dbo].[client_logos] ALTER COLUMN [updated_at] DATETIME2(6) NULL;
