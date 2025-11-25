-- Rollback PKCE configuration settings
ALTER TABLE [dbo].[settings] DROP COLUMN [pkce_required];
ALTER TABLE [dbo].[clients] DROP COLUMN [pkce_required];
