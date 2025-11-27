-- Remove implicit flow settings
ALTER TABLE [dbo].[settings] DROP COLUMN [implicit_flow_enabled];
ALTER TABLE [dbo].[clients] DROP COLUMN [implicit_grant_enabled];
