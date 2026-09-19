-- Add Dynamic Client Registration settings (RFC 7591)
ALTER TABLE [dbo].[settings]
ADD [dynamic_client_registration_enabled] BIT NOT NULL DEFAULT 0;
