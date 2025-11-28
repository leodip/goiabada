-- Goiabada SQL Server Schema
-- This file represents the current database schema after all migrations.
-- Generated from migrations, not intended for direct execution in production.
-- Use migrations for schema changes.

-- Table: clients
CREATE TABLE [clients] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [client_identifier] NVARCHAR(40) NOT NULL,
    [client_secret_encrypted] VARBINARY NULL,
    [description] NVARCHAR(128) NULL,
    [enabled] BIT NOT NULL,
    [consent_required] BIT NOT NULL,
    [is_public] BIT NOT NULL,
    [authorization_code_enabled] BIT NOT NULL,
    [client_credentials_enabled] BIT NOT NULL,
    [token_expiration_in_seconds] INT NOT NULL,
    [refresh_token_offline_idle_timeout_in_seconds] INT NOT NULL,
    [refresh_token_offline_max_lifetime_in_seconds] INT NOT NULL,
    [include_open_id_connect_claims_in_access_token] NVARCHAR(16) NOT NULL,
    [default_acr_level] NVARCHAR(128) NOT NULL,
    [pkce_required] BIT NULL DEFAULT (NULL),
    CONSTRAINT [PK_clients] PRIMARY KEY ([id])
);

-- Table: clients_permissions
CREATE TABLE [clients_permissions] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [client_id] BIGINT NOT NULL,
    [permission_id] BIGINT NOT NULL,
    CONSTRAINT [PK_clients_permissions] PRIMARY KEY ([id])
);

-- Table: codes
CREATE TABLE [codes] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [code_hash] NVARCHAR(64) NOT NULL,
    [client_id] BIGINT NOT NULL,
    [code_challenge] VARCHAR(256) NULL,
    [code_challenge_method] VARCHAR(10) NULL,
    [scope] NVARCHAR(512) NOT NULL,
    [state] NVARCHAR(512) NOT NULL,
    [nonce] NVARCHAR(512) NOT NULL,
    [redirect_uri] NVARCHAR(256) NOT NULL,
    [user_id] BIGINT NOT NULL,
    [ip_address] NVARCHAR(64) NOT NULL,
    [user_agent] NVARCHAR(512) NOT NULL,
    [response_mode] NVARCHAR(16) NOT NULL,
    [authenticated_at] DATETIME2 NOT NULL,
    [session_identifier] NVARCHAR(64) NOT NULL,
    [acr_level] NVARCHAR(128) NOT NULL,
    [auth_methods] NVARCHAR(64) NOT NULL,
    [used] BIT NOT NULL,
    CONSTRAINT [PK_codes] PRIMARY KEY ([id])
);

-- Table: group_attributes
CREATE TABLE [group_attributes] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [key] NVARCHAR(32) NOT NULL,
    [value] NVARCHAR(256) NOT NULL,
    [include_in_id_token] BIT NOT NULL,
    [include_in_access_token] BIT NOT NULL,
    [group_id] BIGINT NOT NULL,
    CONSTRAINT [PK_group_attributes] PRIMARY KEY ([id])
);

-- Table: groups
CREATE TABLE [groups] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [group_identifier] NVARCHAR(40) NOT NULL,
    [description] NVARCHAR(128) NULL,
    [include_in_id_token] BIT NOT NULL,
    [include_in_access_token] BIT NOT NULL,
    CONSTRAINT [PK_groups] PRIMARY KEY ([id])
);

-- Table: groups_permissions
CREATE TABLE [groups_permissions] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [group_id] BIGINT NOT NULL,
    [permission_id] BIGINT NOT NULL,
    CONSTRAINT [PK_groups_permissions] PRIMARY KEY ([id])
);

-- Table: http_sessions
CREATE TABLE [http_sessions] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [data] NVARCHAR(MAX) NULL,
    [expires_on] DATETIME2 NULL,
    CONSTRAINT [PK_http_sessions] PRIMARY KEY ([id])
);

-- Table: key_pairs
CREATE TABLE [key_pairs] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [state] NVARCHAR(191) NOT NULL,
    [key_identifier] NVARCHAR(64) NOT NULL,
    [type] NVARCHAR(16) NOT NULL,
    [algorithm] NVARCHAR(16) NOT NULL,
    [private_key_pem] VARBINARY NULL,
    [public_key_pem] VARBINARY NULL,
    [public_key_asn1_der] VARBINARY NULL,
    [public_key_jwk] VARBINARY NULL,
    CONSTRAINT [PK_key_pairs] PRIMARY KEY ([id])
);

-- Table: permissions
CREATE TABLE [permissions] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [permission_identifier] NVARCHAR(40) NOT NULL,
    [description] NVARCHAR(128) NULL,
    [resource_id] BIGINT NOT NULL,
    CONSTRAINT [PK_permissions] PRIMARY KEY ([id])
);

-- Table: pre_registrations
CREATE TABLE [pre_registrations] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [email] NVARCHAR(64) NULL,
    [password_hash] NVARCHAR(64) NOT NULL,
    [verification_code_encrypted] VARBINARY NULL,
    [verification_code_issued_at] DATETIME2 NULL,
    CONSTRAINT [PK_pre_registrations] PRIMARY KEY ([id])
);

-- Table: redirect_uris
CREATE TABLE [redirect_uris] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [uri] NVARCHAR(256) NOT NULL,
    [client_id] BIGINT NOT NULL,
    CONSTRAINT [PK_redirect_uris] PRIMARY KEY ([id])
);

-- Table: refresh_tokens
CREATE TABLE [refresh_tokens] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [code_id] BIGINT NULL,
    [user_id] BIGINT NULL,
    [client_id] BIGINT NULL,
    [refresh_token_jti] NVARCHAR(64) NOT NULL,
    [previous_refresh_token_jti] NVARCHAR(64) NOT NULL,
    [first_refresh_token_jti] NVARCHAR(64) NOT NULL,
    [session_identifier] NVARCHAR(64) NOT NULL,
    [refresh_token_type] NVARCHAR(16) NOT NULL,
    [scope] NVARCHAR(512) NOT NULL,
    [issued_at] DATETIME2 NULL,
    [expires_at] DATETIME2 NULL,
    [max_lifetime] DATETIME2 NULL,
    [revoked] BIT NOT NULL,
    CONSTRAINT [PK_refresh_tokens] PRIMARY KEY ([id])
);

-- Table: resources
CREATE TABLE [resources] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [resource_identifier] NVARCHAR(40) NOT NULL,
    [description] NVARCHAR(128) NULL,
    CONSTRAINT [PK_resources] PRIMARY KEY ([id])
);

-- Table: schema_migrations
CREATE TABLE [schema_migrations] (
    [version] BIGINT NOT NULL,
    [dirty] BIT NOT NULL,
    CONSTRAINT [PK_schema_migrations] PRIMARY KEY ([version])
);

-- Table: settings
CREATE TABLE [settings] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [app_name] NVARCHAR(32) NOT NULL,
    [issuer] NVARCHAR(64) NOT NULL,
    [ui_theme] NVARCHAR(32) NOT NULL,
    [password_policy] INT NULL,
    [self_registration_enabled] BIT NOT NULL,
    [self_registration_requires_email_verification] BIT NOT NULL,
    [token_expiration_in_seconds] INT NOT NULL,
    [refresh_token_offline_idle_timeout_in_seconds] INT NOT NULL,
    [refresh_token_offline_max_lifetime_in_seconds] INT NOT NULL,
    [user_session_idle_timeout_in_seconds] INT NOT NULL,
    [user_session_max_lifetime_in_seconds] INT NOT NULL,
    [include_open_id_connect_claims_in_access_token] BIT NOT NULL,
    [aes_encryption_key] VARBINARY NOT NULL,
    [smtp_host] NVARCHAR(128) NULL,
    [smtp_port] INT NULL,
    [smtp_username] NVARCHAR(64) NULL,
    [smtp_password_encrypted] VARBINARY NULL,
    [smtp_from_name] NVARCHAR(64) NULL,
    [smtp_from_email] NVARCHAR(64) NULL,
    [smtp_encryption] NVARCHAR(16) NULL,
    [smtp_enabled] BIT NOT NULL,
    [dynamic_client_registration_enabled] BIT NOT NULL DEFAULT ((0)),
    [pkce_required] BIT NOT NULL DEFAULT ((1)),
    CONSTRAINT [PK_settings] PRIMARY KEY ([id])
);

-- Table: user_attributes
CREATE TABLE [user_attributes] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [key] NVARCHAR(32) NOT NULL,
    [value] NVARCHAR(256) NOT NULL,
    [include_in_id_token] BIT NOT NULL,
    [include_in_access_token] BIT NOT NULL,
    [user_id] BIGINT NOT NULL,
    CONSTRAINT [PK_user_attributes] PRIMARY KEY ([id])
);

-- Table: user_consents
CREATE TABLE [user_consents] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [user_id] BIGINT NOT NULL,
    [client_id] BIGINT NOT NULL,
    [scope] NVARCHAR(512) NOT NULL,
    [granted_at] DATETIME2 NULL,
    CONSTRAINT [PK_user_consents] PRIMARY KEY ([id])
);

-- Table: user_profile_pictures
CREATE TABLE [user_profile_pictures] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [user_id] BIGINT NOT NULL,
    [picture] VARBINARY NOT NULL,
    [content_type] VARCHAR(64) NOT NULL,
    CONSTRAINT [PK_user_profile_pictures] PRIMARY KEY ([id])
);

-- Table: user_session_clients
CREATE TABLE [user_session_clients] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [user_session_id] BIGINT NOT NULL,
    [client_id] BIGINT NOT NULL,
    [started] DATETIME2 NOT NULL,
    [last_accessed] DATETIME2 NOT NULL,
    CONSTRAINT [PK_user_session_clients] PRIMARY KEY ([id])
);

-- Table: user_sessions
CREATE TABLE [user_sessions] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [session_identifier] NVARCHAR(64) NOT NULL,
    [started] DATETIME2 NOT NULL,
    [last_accessed] DATETIME2 NOT NULL,
    [auth_methods] NVARCHAR(64) NOT NULL,
    [acr_level] NVARCHAR(128) NOT NULL,
    [auth_time] DATETIME2 NOT NULL,
    [ip_address] NVARCHAR(512) NOT NULL,
    [device_name] NVARCHAR(256) NOT NULL,
    [device_type] NVARCHAR(32) NOT NULL,
    [device_os] NVARCHAR(64) NOT NULL,
    [level2_auth_config_has_changed] BIT NOT NULL,
    [user_id] BIGINT NOT NULL,
    CONSTRAINT [PK_user_sessions] PRIMARY KEY ([id])
);

-- Table: users
CREATE TABLE [users] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [enabled] BIT NOT NULL,
    [subject] NVARCHAR(64) NOT NULL,
    [username] NVARCHAR(32) NOT NULL,
    [given_name] NVARCHAR(64) NULL,
    [middle_name] NVARCHAR(64) NULL,
    [family_name] NVARCHAR(64) NULL,
    [nickname] NVARCHAR(64) NULL,
    [website] NVARCHAR(128) NULL,
    [gender] NVARCHAR(16) NULL,
    [email] NVARCHAR(64) NULL,
    [email_verified] BIT NOT NULL,
    [email_verification_code_encrypted] VARBINARY NULL,
    [email_verification_code_issued_at] DATETIME2 NULL,
    [zone_info_country_name] NVARCHAR(128) NULL,
    [zone_info] NVARCHAR(128) NULL,
    [locale] NVARCHAR(32) NULL,
    [birth_date] DATETIME2 NULL,
    [phone_number] NVARCHAR(32) NULL,
    [phone_number_country_uniqueid] NVARCHAR(16) NULL,
    [phone_number_country_callingcode] NVARCHAR(16) NULL,
    [phone_number_verified] BIT NOT NULL,
    [phone_number_verification_code_encrypted] VARBINARY NULL,
    [phone_number_verification_code_issued_at] DATETIME2 NULL,
    [address_line1] NVARCHAR(64) NULL,
    [address_line2] NVARCHAR(64) NULL,
    [address_locality] NVARCHAR(64) NULL,
    [address_region] NVARCHAR(64) NULL,
    [address_postal_code] NVARCHAR(32) NULL,
    [address_country] NVARCHAR(32) NULL,
    [password_hash] NVARCHAR(64) NOT NULL,
    [otp_secret] NVARCHAR(64) NULL,
    [otp_enabled] BIT NOT NULL,
    [forgot_password_code_encrypted] VARBINARY NULL,
    [forgot_password_code_issued_at] DATETIME2 NULL,
    CONSTRAINT [PK_users] PRIMARY KEY ([id])
);

-- Table: users_groups
CREATE TABLE [users_groups] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [group_id] BIGINT NOT NULL,
    [user_id] BIGINT NOT NULL,
    CONSTRAINT [PK_users_groups] PRIMARY KEY ([id])
);

-- Table: users_permissions
CREATE TABLE [users_permissions] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [updated_at] DATETIME2 NULL,
    [user_id] BIGINT NOT NULL,
    [permission_id] BIGINT NOT NULL,
    CONSTRAINT [PK_users_permissions] PRIMARY KEY ([id])
);

-- Table: web_origins
CREATE TABLE [web_origins] (
    [id] BIGINT IDENTITY(1,1) NOT NULL,
    [created_at] DATETIME2 NULL,
    [origin] NVARCHAR(256) NOT NULL,
    [client_id] BIGINT NOT NULL,
    CONSTRAINT [PK_web_origins] PRIMARY KEY ([id])
);

-- Foreign Key Constraints
ALTER TABLE [clients_permissions] ADD CONSTRAINT [fk_clients_permissions_client] FOREIGN KEY ([client_id]) REFERENCES [clients]([id]) ON DELETE CASCADE;
ALTER TABLE [clients_permissions] ADD CONSTRAINT [fk_clients_permissions_permission] FOREIGN KEY ([permission_id]) REFERENCES [permissions]([id]) ON DELETE CASCADE;
ALTER TABLE [codes] ADD CONSTRAINT [fk_codes_client] FOREIGN KEY ([client_id]) REFERENCES [clients]([id]) ON DELETE CASCADE;
ALTER TABLE [codes] ADD CONSTRAINT [fk_codes_user] FOREIGN KEY ([user_id]) REFERENCES [users]([id]) ON DELETE CASCADE;
ALTER TABLE [group_attributes] ADD CONSTRAINT [fk_groups_attributes] FOREIGN KEY ([group_id]) REFERENCES [groups]([id]) ON DELETE CASCADE;
ALTER TABLE [groups_permissions] ADD CONSTRAINT [fk_groups_permissions_group] FOREIGN KEY ([group_id]) REFERENCES [groups]([id]) ON DELETE CASCADE;
ALTER TABLE [groups_permissions] ADD CONSTRAINT [fk_groups_permissions_permission] FOREIGN KEY ([permission_id]) REFERENCES [permissions]([id]) ON DELETE CASCADE;
ALTER TABLE [permissions] ADD CONSTRAINT [fk_permissions_resource] FOREIGN KEY ([resource_id]) REFERENCES [resources]([id]) ON DELETE CASCADE;
ALTER TABLE [redirect_uris] ADD CONSTRAINT [fk_clients_redirect_uris] FOREIGN KEY ([client_id]) REFERENCES [clients]([id]) ON DELETE CASCADE;
ALTER TABLE [refresh_tokens] ADD CONSTRAINT [fk_refresh_tokens_code] FOREIGN KEY ([code_id]) REFERENCES [codes]([id]) ON DELETE CASCADE;
ALTER TABLE [refresh_tokens] ADD CONSTRAINT [fk_refresh_tokens_user] FOREIGN KEY ([user_id]) REFERENCES [users]([id]) ON DELETE NO ACTION;
ALTER TABLE [refresh_tokens] ADD CONSTRAINT [fk_refresh_tokens_client] FOREIGN KEY ([client_id]) REFERENCES [clients]([id]) ON DELETE NO ACTION;
ALTER TABLE [user_attributes] ADD CONSTRAINT [fk_users_attributes] FOREIGN KEY ([user_id]) REFERENCES [users]([id]) ON DELETE CASCADE;
ALTER TABLE [user_consents] ADD CONSTRAINT [fk_user_consents_client] FOREIGN KEY ([client_id]) REFERENCES [clients]([id]) ON DELETE CASCADE;
ALTER TABLE [user_consents] ADD CONSTRAINT [fk_user_consents_user] FOREIGN KEY ([user_id]) REFERENCES [users]([id]) ON DELETE CASCADE;
ALTER TABLE [user_profile_pictures] ADD CONSTRAINT [fk_user_profile_pictures_user_id] FOREIGN KEY ([user_id]) REFERENCES [users]([id]) ON DELETE CASCADE;
ALTER TABLE [user_session_clients] ADD CONSTRAINT [fk_user_session_clients_client] FOREIGN KEY ([client_id]) REFERENCES [clients]([id]) ON DELETE CASCADE;
ALTER TABLE [user_session_clients] ADD CONSTRAINT [fk_user_sessions_clients] FOREIGN KEY ([user_session_id]) REFERENCES [user_sessions]([id]) ON DELETE CASCADE;
ALTER TABLE [user_sessions] ADD CONSTRAINT [fk_user_sessions_user] FOREIGN KEY ([user_id]) REFERENCES [users]([id]) ON DELETE CASCADE;
ALTER TABLE [users_groups] ADD CONSTRAINT [fk_users_groups_group] FOREIGN KEY ([group_id]) REFERENCES [groups]([id]) ON DELETE CASCADE;
ALTER TABLE [users_groups] ADD CONSTRAINT [fk_users_groups_user] FOREIGN KEY ([user_id]) REFERENCES [users]([id]) ON DELETE CASCADE;
ALTER TABLE [users_permissions] ADD CONSTRAINT [fk_users_permissions_permission] FOREIGN KEY ([permission_id]) REFERENCES [permissions]([id]) ON DELETE CASCADE;
ALTER TABLE [users_permissions] ADD CONSTRAINT [fk_users_permissions_user] FOREIGN KEY ([user_id]) REFERENCES [users]([id]) ON DELETE CASCADE;
ALTER TABLE [web_origins] ADD CONSTRAINT [fk_clients_web_origins] FOREIGN KEY ([client_id]) REFERENCES [clients]([id]) ON DELETE CASCADE;

-- Indexes
CREATE UNIQUE INDEX [idx_client_identifier] ON [clients] (client_identifier);
CREATE UNIQUE INDEX [idx_code_hash] ON [codes] (code_hash);
CREATE UNIQUE INDEX [idx_group_identifier] ON [groups] (group_identifier);
CREATE INDEX [idx_httpsess_expires] ON [http_sessions] (expires_on);
CREATE INDEX [idx_state] ON [key_pairs] (state);
CREATE UNIQUE INDEX [idx_permission_identifier_resource] ON [permissions] (permission_identifier, resource_id);
CREATE INDEX [idx_pre_reg_email] ON [pre_registrations] (email);
CREATE UNIQUE INDEX [idx_refresh_token_jti] ON [refresh_tokens] (refresh_token_jti);
CREATE INDEX [idx_refresh_tokens_user_id] ON [refresh_tokens] ([user_id]);
CREATE INDEX [idx_refresh_tokens_client_id] ON [refresh_tokens] ([client_id]);
CREATE UNIQUE INDEX [idx_resource_identifier] ON [resources] (resource_identifier);
CREATE UNIQUE INDEX [UQ__user_pro__B9BE370E38AE34F6] ON [user_profile_pictures] (user_id);
CREATE UNIQUE INDEX [idx_session_identifier] ON [user_sessions] (session_identifier);
CREATE UNIQUE INDEX [idx_email] ON [users] (email);
CREATE INDEX [idx_family_name] ON [users] (family_name);
CREATE INDEX [idx_given_name] ON [users] (given_name);
CREATE INDEX [idx_middle_name] ON [users] (middle_name);
CREATE UNIQUE INDEX [idx_subject] ON [users] (subject);
CREATE INDEX [idx_username] ON [users] (username);
