-- 000001_initial_create.down.sql

DROP TABLE IF EXISTS [dbo].[web_origins];
DROP TABLE IF EXISTS [dbo].[users_permissions];
DROP TABLE IF EXISTS [dbo].[users_groups];
DROP TABLE IF EXISTS [dbo].[user_session_clients];
DROP TABLE IF EXISTS [dbo].[user_consents];
DROP TABLE IF EXISTS [dbo].[user_attributes];
DROP TABLE IF EXISTS [dbo].[refresh_tokens];
DROP TABLE IF EXISTS [dbo].[redirect_uris];
DROP TABLE IF EXISTS [dbo].[groups_permissions];
DROP TABLE IF EXISTS [dbo].[clients_permissions];
DROP TABLE IF EXISTS [dbo].[group_attributes];
DROP TABLE IF EXISTS [dbo].[codes];
DROP TABLE IF EXISTS [dbo].[permissions];
DROP TABLE IF EXISTS [dbo].[user_sessions];
DROP TABLE IF EXISTS [dbo].[users];
DROP TABLE IF EXISTS [dbo].[settings];
DROP TABLE IF EXISTS [dbo].[resources];
DROP TABLE IF EXISTS [dbo].[pre_registrations];
DROP TABLE IF EXISTS [dbo].[key_pairs];
DROP TABLE IF EXISTS [dbo].[http_sessions];
DROP TABLE IF EXISTS [dbo].[groups];
DROP TABLE IF EXISTS [dbo].[clients];

-- end 