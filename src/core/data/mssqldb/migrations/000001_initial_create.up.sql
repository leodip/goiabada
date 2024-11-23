-- 000001_initial_create.up.sql

-- Create base tables that don't depend on other tables
CREATE TABLE [dbo].[resources] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [resource_identifier] NVARCHAR(40) NOT NULL,
    [description] NVARCHAR(128)
);

CREATE TABLE [dbo].[clients] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [client_identifier] NVARCHAR(40) NOT NULL,
    [client_secret_encrypted] VARBINARY(MAX),
    [description] NVARCHAR(128),
    [enabled] BIT NOT NULL,
    [consent_required] BIT NOT NULL,
    [is_public] BIT NOT NULL,
    [authorization_code_enabled] BIT NOT NULL,
    [client_credentials_enabled] BIT NOT NULL,
    [token_expiration_in_seconds] INT NOT NULL,
    [refresh_token_offline_idle_timeout_in_seconds] INT NOT NULL,
    [refresh_token_offline_max_lifetime_in_seconds] INT NOT NULL,
    [include_open_id_connect_claims_in_access_token] NVARCHAR(16) NOT NULL,
    [default_acr_level] NVARCHAR(128) NOT NULL
);

CREATE TABLE [dbo].[groups] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [group_identifier] NVARCHAR(40) NOT NULL,
    [description] NVARCHAR(128),
    [include_in_id_token] BIT NOT NULL,
    [include_in_access_token] BIT NOT NULL
);

CREATE TABLE [dbo].[users] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [enabled] BIT NOT NULL,
    [subject] NVARCHAR(64) NOT NULL,
    [username] NVARCHAR(32) NOT NULL,
    [given_name] NVARCHAR(64),
    [middle_name] NVARCHAR(64),
    [family_name] NVARCHAR(64),
    [nickname] NVARCHAR(64),
    [website] NVARCHAR(128),
    [gender] NVARCHAR(16),
    [email] NVARCHAR(64),
    [email_verified] BIT NOT NULL,
    [email_verification_code_encrypted] VARBINARY(MAX),
    [email_verification_code_issued_at] datetime2(6),
    [zone_info_country_name] NVARCHAR(128),
    [zone_info] NVARCHAR(128),
    [locale] NVARCHAR(32),
    [birth_date] datetime2(6),
    [phone_number] NVARCHAR(32),
    [phone_number_country_uniqueid] NVARCHAR(16),
    [phone_number_country_callingcode] NVARCHAR(16),
    [phone_number_verified] BIT NOT NULL,
    [phone_number_verification_code_encrypted] VARBINARY(MAX),
    [phone_number_verification_code_issued_at] datetime2(6),
    [address_line1] NVARCHAR(64),
    [address_line2] NVARCHAR(64),
    [address_locality] NVARCHAR(64),
    [address_region] NVARCHAR(64),
    [address_postal_code] NVARCHAR(32),
    [address_country] NVARCHAR(32),
    [password_hash] NVARCHAR(64) NOT NULL,
    [otp_secret] NVARCHAR(64),
    [otp_enabled] BIT NOT NULL,
    [forgot_password_code_encrypted] VARBINARY(MAX),
    [forgot_password_code_issued_at] datetime2(6)
);

CREATE TABLE [dbo].[http_sessions] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [data] NVARCHAR(MAX),
    [expires_on] datetime2(6)
);

CREATE TABLE [dbo].[key_pairs] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [state] NVARCHAR(191) NOT NULL,
    [key_identifier] NVARCHAR(64) NOT NULL,
    [type] NVARCHAR(16) NOT NULL,
    [algorithm] NVARCHAR(16) NOT NULL,
    [private_key_pem] VARBINARY(MAX),
    [public_key_pem] VARBINARY(MAX),
    [public_key_asn1_der] VARBINARY(MAX),
    [public_key_jwk] VARBINARY(MAX)
);

CREATE TABLE [dbo].[permissions] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [permission_identifier] NVARCHAR(40) NOT NULL,
    [description] NVARCHAR(128),
    [resource_id] BIGINT NOT NULL,
    CONSTRAINT [fk_permissions_resource] FOREIGN KEY ([resource_id]) 
        REFERENCES [dbo].[resources] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[pre_registrations] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [email] NVARCHAR(64),
    [password_hash] NVARCHAR(64) NOT NULL,
    [verification_code_encrypted] VARBINARY(MAX),
    [verification_code_issued_at] datetime2(6)
);

CREATE TABLE [dbo].[settings] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [app_name] NVARCHAR(32) NOT NULL,
    [issuer] NVARCHAR(64) NOT NULL,
    [ui_theme] NVARCHAR(32) NOT NULL,
    [password_policy] INT,
    [self_registration_enabled] BIT NOT NULL,
    [self_registration_requires_email_verification] BIT NOT NULL,
    [token_expiration_in_seconds] INT NOT NULL,
    [refresh_token_offline_idle_timeout_in_seconds] INT NOT NULL,
    [refresh_token_offline_max_lifetime_in_seconds] INT NOT NULL,
    [user_session_idle_timeout_in_seconds] INT NOT NULL,
    [user_session_max_lifetime_in_seconds] INT NOT NULL,
    [include_open_id_connect_claims_in_access_token] BIT NOT NULL,
    [session_authentication_key] VARBINARY(MAX) NOT NULL,
    [session_encryption_key] VARBINARY(MAX) NOT NULL,
    [aes_encryption_key] VARBINARY(MAX) NOT NULL,
    [smtp_host] NVARCHAR(128),
    [smtp_port] INT,
    [smtp_username] NVARCHAR(64),
    [smtp_password_encrypted] VARBINARY(MAX),
    [smtp_from_name] NVARCHAR(64),
    [smtp_from_email] NVARCHAR(64),
    [smtp_encryption] NVARCHAR(16),
    [smtp_enabled] BIT NOT NULL
);

CREATE TABLE [dbo].[codes] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [code_hash] NVARCHAR(64) NOT NULL,
    [client_id] BIGINT NOT NULL,
    [code_challenge] NVARCHAR(256) NOT NULL,
    [code_challenge_method] NVARCHAR(10) NOT NULL,
    [scope] NVARCHAR(512) NOT NULL,
    [state] NVARCHAR(512) NOT NULL,
    [nonce] NVARCHAR(512) NOT NULL,
    [redirect_uri] NVARCHAR(256) NOT NULL,
    [user_id] BIGINT NOT NULL,
    [ip_address] NVARCHAR(64) NOT NULL,
    [user_agent] NVARCHAR(512) NOT NULL,
    [response_mode] NVARCHAR(16) NOT NULL,
    [authenticated_at] datetime2(6) NOT NULL,
    [session_identifier] NVARCHAR(64) NOT NULL,
    [acr_level] NVARCHAR(128) NOT NULL,
    [auth_methods] NVARCHAR(64) NOT NULL,
    [used] BIT NOT NULL,
    CONSTRAINT [fk_codes_client] FOREIGN KEY ([client_id]) 
        REFERENCES [dbo].[clients] ([id]) ON DELETE CASCADE,
    CONSTRAINT [fk_codes_user] FOREIGN KEY ([user_id]) 
        REFERENCES [dbo].[users] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[group_attributes] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [key] NVARCHAR(32) NOT NULL,
    [value] NVARCHAR(256) NOT NULL,
    [include_in_id_token] BIT NOT NULL,
    [include_in_access_token] BIT NOT NULL,
    [group_id] BIGINT NOT NULL,
    CONSTRAINT [fk_groups_attributes] FOREIGN KEY ([group_id]) 
        REFERENCES [dbo].[groups] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[clients_permissions] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [client_id] BIGINT NOT NULL,
    [permission_id] BIGINT NOT NULL,
    CONSTRAINT [fk_clients_permissions_client] FOREIGN KEY ([client_id]) 
        REFERENCES [dbo].[clients] ([id]) ON DELETE CASCADE,
    CONSTRAINT [fk_clients_permissions_permission] FOREIGN KEY ([permission_id]) 
        REFERENCES [dbo].[permissions] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[groups_permissions] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [group_id] BIGINT NOT NULL,
    [permission_id] BIGINT NOT NULL,
    CONSTRAINT [fk_groups_permissions_group] FOREIGN KEY ([group_id]) 
        REFERENCES [dbo].[groups] ([id]) ON DELETE CASCADE,
    CONSTRAINT [fk_groups_permissions_permission] FOREIGN KEY ([permission_id]) 
        REFERENCES [dbo].[permissions] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[redirect_uris] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [uri] NVARCHAR(256) NOT NULL,
    [client_id] BIGINT NOT NULL,
    CONSTRAINT [fk_clients_redirect_uris] FOREIGN KEY ([client_id]) 
        REFERENCES [dbo].[clients] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[refresh_tokens] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [code_id] BIGINT NOT NULL,
    [refresh_token_jti] NVARCHAR(64) NOT NULL,
    [previous_refresh_token_jti] NVARCHAR(64) NOT NULL,
    [first_refresh_token_jti] NVARCHAR(64) NOT NULL,
    [session_identifier] NVARCHAR(64) NOT NULL,
    [refresh_token_type] NVARCHAR(16) NOT NULL,
    [scope] NVARCHAR(512) NOT NULL,
    [issued_at] datetime2(6),
    [expires_at] datetime2(6),
    [max_lifetime] datetime2(6),
    [revoked] BIT NOT NULL,
    CONSTRAINT [fk_refresh_tokens_code] FOREIGN KEY ([code_id]) 
        REFERENCES [dbo].[codes] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[user_attributes] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [key] NVARCHAR(32) NOT NULL,
    [value] NVARCHAR(256) NOT NULL,
    [include_in_id_token] BIT NOT NULL,
    [include_in_access_token] BIT NOT NULL,
    [user_id] BIGINT NOT NULL,
    CONSTRAINT [fk_users_attributes] FOREIGN KEY ([user_id]) 
        REFERENCES [dbo].[users] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[user_consents] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [user_id] BIGINT NOT NULL,
    [client_id] BIGINT NOT NULL,
    [scope] NVARCHAR(512) NOT NULL,
    [granted_at] datetime2(6),
    CONSTRAINT [fk_user_consents_client] FOREIGN KEY ([client_id]) 
        REFERENCES [dbo].[clients] ([id]) ON DELETE CASCADE,
    CONSTRAINT [fk_user_consents_user] FOREIGN KEY ([user_id]) 
        REFERENCES [dbo].[users] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[user_sessions] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [session_identifier] NVARCHAR(64) NOT NULL,
    [started] datetime2(6) NOT NULL,
    [last_accessed] datetime2(6) NOT NULL,
    [auth_methods] NVARCHAR(64) NOT NULL,
    [acr_level] NVARCHAR(128) NOT NULL,
    [auth_time] datetime2(6) NOT NULL,
    [ip_address] NVARCHAR(512) NOT NULL,
    [device_name] NVARCHAR(256) NOT NULL,
    [device_type] NVARCHAR(32) NOT NULL,
    [device_os] NVARCHAR(64) NOT NULL,
    [level2_auth_config_has_changed] BIT NOT NULL,
    [user_id] BIGINT NOT NULL,
    CONSTRAINT [fk_user_sessions_user] FOREIGN KEY ([user_id]) 
        REFERENCES [dbo].[users] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[user_session_clients] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [user_session_id] BIGINT NOT NULL,
    [client_id] BIGINT NOT NULL,
    [started] datetime2(6) NOT NULL,
    [last_accessed] datetime2(6) NOT NULL,
    CONSTRAINT [fk_user_sessions_clients] FOREIGN KEY ([user_session_id]) 
        REFERENCES [dbo].[user_sessions] ([id]) ON DELETE CASCADE,
    CONSTRAINT [fk_user_session_clients_client] FOREIGN KEY ([client_id]) 
        REFERENCES [dbo].[clients] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[users_groups] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [group_id] BIGINT NOT NULL,
    [user_id] BIGINT NOT NULL,
    CONSTRAINT [fk_users_groups_group] FOREIGN KEY ([group_id]) 
        REFERENCES [dbo].[groups] ([id]) ON DELETE CASCADE,
    CONSTRAINT [fk_users_groups_user] FOREIGN KEY ([user_id]) 
        REFERENCES [dbo].[users] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[users_permissions] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [user_id] BIGINT NOT NULL,
    [permission_id] BIGINT NOT NULL,
    CONSTRAINT [fk_users_permissions_user] FOREIGN KEY ([user_id]) 
        REFERENCES [dbo].[users] ([id]) ON DELETE CASCADE,
    CONSTRAINT [fk_users_permissions_permission] FOREIGN KEY ([permission_id]) 
        REFERENCES [dbo].[permissions] ([id]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[web_origins] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [origin] NVARCHAR(256) NOT NULL,
    [client_id] BIGINT NOT NULL,
    CONSTRAINT [fk_clients_web_origins] FOREIGN KEY ([client_id]) 
        REFERENCES [dbo].[clients] ([id]) ON DELETE CASCADE
);

-- Create unique indexes
CREATE UNIQUE NONCLUSTERED INDEX [idx_client_identifier] ON [dbo].[clients] ([client_identifier]);
CREATE UNIQUE NONCLUSTERED INDEX [idx_resource_identifier] ON [dbo].[resources] ([resource_identifier]);
CREATE UNIQUE NONCLUSTERED INDEX [idx_permission_identifier_resource] ON [dbo].[permissions] ([permission_identifier], [resource_id]);
CREATE UNIQUE NONCLUSTERED INDEX [idx_subject] ON [dbo].[users] ([subject]);
CREATE UNIQUE NONCLUSTERED INDEX [idx_email] ON [dbo].[users] ([email]);
CREATE UNIQUE NONCLUSTERED INDEX [idx_code_hash] ON [dbo].[codes] ([code_hash]);
CREATE UNIQUE NONCLUSTERED INDEX [idx_group_identifier] ON [dbo].[groups] ([group_identifier]);
CREATE UNIQUE NONCLUSTERED INDEX [idx_refresh_token_jti] ON [dbo].[refresh_tokens] ([refresh_token_jti]);
CREATE UNIQUE NONCLUSTERED INDEX [idx_session_identifier] ON [dbo].[user_sessions] ([session_identifier]);

-- Create regular indexes
CREATE NONCLUSTERED INDEX [idx_username] ON [dbo].[users] ([username]);
CREATE NONCLUSTERED INDEX [idx_given_name] ON [dbo].[users] ([given_name]);
CREATE NONCLUSTERED INDEX [idx_middle_name] ON [dbo].[users] ([middle_name]);
CREATE NONCLUSTERED INDEX [idx_family_name] ON [dbo].[users] ([family_name]);
CREATE NONCLUSTERED INDEX [idx_httpsess_expires] ON [dbo].[http_sessions] ([expires_on]);
CREATE NONCLUSTERED INDEX [idx_state] ON [dbo].[key_pairs] ([state]);
CREATE NONCLUSTERED INDEX [idx_pre_reg_email] ON [dbo].[pre_registrations] ([email]);

-- end
