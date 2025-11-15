-- Rollback Dynamic Client Registration settings
ALTER TABLE [dbo].[settings] DROP COLUMN [dynamic_client_registration_enabled];
