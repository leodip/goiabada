-- Goiabada SQLite Schema
-- This file represents the current database schema after all migrations.
-- Generated from migrations, not intended for direct execution in production.
-- Use migrations for schema changes.

CREATE TABLE schema_migrations (version uint64,dirty bool);
CREATE UNIQUE INDEX version_unique ON schema_migrations (version);

CREATE TABLE clients (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  client_identifier TEXT NOT NULL,
  client_secret_encrypted BLOB,
  `description` TEXT,
  `website_url` TEXT NOT NULL DEFAULT '',
  display_name TEXT NOT NULL DEFAULT '',
  `enabled` numeric NOT NULL,
  consent_required numeric NOT NULL,
  show_logo INTEGER NOT NULL DEFAULT 0,
  show_display_name INTEGER NOT NULL DEFAULT 0,
  show_description INTEGER NOT NULL DEFAULT 0,
  show_website_url INTEGER NOT NULL DEFAULT 0,
  is_public numeric NOT NULL,
  authorization_code_enabled numeric NOT NULL,
  client_credentials_enabled numeric NOT NULL,
  token_expiration_in_seconds int NOT NULL,
  refresh_token_offline_idle_timeout_in_seconds int NOT NULL,
  refresh_token_offline_max_lifetime_in_seconds int NOT NULL,
  include_open_id_connect_claims_in_access_token TEXT NOT NULL,
  include_open_id_connect_claims_in_id_token VARCHAR(10) NOT NULL DEFAULT 'default',
  default_acr_level TEXT NOT NULL,
  pkce_required BOOLEAN DEFAULT NULL,
  implicit_grant_enabled BOOLEAN DEFAULT NULL,
  resource_owner_password_credentials_enabled INTEGER DEFAULT NULL
);

CREATE TABLE resources (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  resource_identifier TEXT NOT NULL,
  `description` TEXT  
);

CREATE TABLE permissions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  permission_identifier TEXT NOT NULL,
  `description` TEXT,
  resource_id INTEGER NOT NULL,      
  CONSTRAINT fk_permissions_resource FOREIGN KEY (resource_id) REFERENCES resources (id) ON DELETE CASCADE
);

CREATE TABLE clients_permissions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  client_id INTEGER NOT NULL,  
  permission_id INTEGER NOT NULL,      
  CONSTRAINT fk_clients_permissions_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
  CONSTRAINT fk_clients_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE TABLE users (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  `enabled` numeric NOT NULL,
  `subject` TEXT NOT NULL,
  `username` TEXT NOT NULL,
  given_name TEXT,
  middle_name TEXT,
  family_name TEXT,
  nickname TEXT,
  website TEXT,
  gender TEXT,
  email TEXT,
  email_verified numeric NOT NULL,
  email_verification_code_encrypted BLOB,
  email_verification_code_issued_at DATETIME,
  zone_info_country_name TEXT,
  zone_info TEXT,
  locale TEXT,
  birth_date DATETIME,
  phone_number TEXT,
  phone_number_verified numeric NOT NULL,
  phone_number_verification_code_encrypted BLOB,
  phone_number_verification_code_issued_at DATETIME,
  address_line1 TEXT,
  address_line2 TEXT,
  address_locality TEXT,
  address_region TEXT,
  address_postal_code TEXT,
  address_country TEXT,
  password_hash TEXT NOT NULL,
  otp_secret TEXT,
  otp_enabled numeric NOT NULL,
  forgot_password_code_encrypted BLOB,
  forgot_password_code_issued_at DATETIME
, phone_number_country_uniqueid TEXT, phone_number_country_callingcode TEXT);

CREATE TABLE codes (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  code_hash TEXT NOT NULL,
  client_id INTEGER NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  scope TEXT NOT NULL,
  `state` TEXT NOT NULL,
  nonce TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  ip_address TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  response_mode TEXT NOT NULL,
  authenticated_at DATETIME NOT NULL,
  session_identifier TEXT NOT NULL,
  acr_level TEXT NOT NULL,
  auth_methods TEXT NOT NULL,
  used numeric NOT NULL,  
  CONSTRAINT fk_codes_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
  CONSTRAINT fk_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE groups (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  group_identifier TEXT NOT NULL,
  `description` TEXT,
  include_in_id_token numeric NOT NULL,
  include_in_access_token numeric NOT NULL  
);

CREATE TABLE group_attributes (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  `key` TEXT NOT NULL,
  `value` TEXT NOT NULL,
  include_in_id_token numeric NOT NULL,
  include_in_access_token numeric NOT NULL,
  group_id INTEGER NOT NULL,  
  CONSTRAINT fk_groups_attributes FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE
);

CREATE TABLE groups_permissions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  group_id INTEGER NOT NULL,
  permission_id INTEGER NOT NULL,    
  CONSTRAINT fk_groups_permissions_group FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
  CONSTRAINT fk_groups_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE TABLE http_sessions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  `data` longtext,  
  expires_on DATETIME  
);

CREATE TABLE key_pairs (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  `state` TEXT NOT NULL,
  key_identifier TEXT NOT NULL,
  `type` TEXT NOT NULL,
  `algorithm` TEXT NOT NULL,
  private_key_pem BLOB,
  public_key_pem BLOB,
  public_key_asn1_der BLOB,
  public_key_jwk BLOB
);

CREATE TABLE pre_registrations (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  email TEXT,
  password_hash TEXT NOT NULL,
  verification_code_encrypted BLOB,
  verification_code_issued_at DATETIME
);

CREATE TABLE redirect_uris (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  uri TEXT NOT NULL,
  client_id INTEGER NOT NULL,  
  CONSTRAINT fk_clients_redirect_uris FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

CREATE TABLE refresh_tokens (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  code_id INTEGER NULL,
  user_id INTEGER NULL,
  client_id INTEGER NULL,
  refresh_token_jti TEXT NOT NULL,
  previous_refresh_token_jti TEXT NOT NULL,
  first_refresh_token_jti TEXT NOT NULL,
  session_identifier TEXT NOT NULL,
  refresh_token_type TEXT NOT NULL,
  scope TEXT NOT NULL,
  issued_at DATETIME,
  expires_at DATETIME,
  max_lifetime DATETIME,
  revoked numeric NOT NULL,
  CONSTRAINT fk_refresh_tokens_code FOREIGN KEY (code_id) REFERENCES codes (id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_tokens_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

CREATE TABLE user_attributes (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  `key` TEXT NOT NULL,
  `value` TEXT NOT NULL,
  include_in_id_token numeric NOT NULL,
  include_in_access_token numeric NOT NULL,
  user_id INTEGER NOT NULL,    
  CONSTRAINT fk_users_attributes FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE user_consents (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  user_id INTEGER NOT NULL,
  client_id INTEGER NOT NULL,
  scope TEXT NOT NULL,
  granted_at DATETIME,  
  CONSTRAINT fk_user_consents_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
  CONSTRAINT fk_user_consents_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE user_sessions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  session_identifier TEXT NOT NULL,
  `started` DATETIME NOT NULL,
  last_accessed DATETIME NOT NULL,
  auth_methods TEXT NOT NULL,
  acr_level TEXT NOT NULL,
  auth_time DATETIME NOT NULL,
  ip_address TEXT NOT NULL,
  device_name TEXT NOT NULL,
  device_type TEXT NOT NULL,
  device_os TEXT NOT NULL,
  user_id INTEGER NOT NULL, level2_auth_config_has_changed INTEGER NOT NULL DEFAULT 0,  
  CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE user_session_clients (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  user_session_id INTEGER NOT NULL,
  client_id INTEGER NOT NULL,
  `started` DATETIME NOT NULL,
  last_accessed DATETIME NOT NULL,  
  CONSTRAINT fk_user_sessions_clients FOREIGN KEY (user_session_id) REFERENCES user_sessions (id) ON DELETE CASCADE,
  CONSTRAINT fk_user_session_clients_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

CREATE TABLE users_groups (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  group_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,  
  CONSTRAINT fk_users_groups_group FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
  CONSTRAINT fk_users_groups_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE users_permissions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  user_id INTEGER NOT NULL,
  permission_id INTEGER NOT NULL,  
  CONSTRAINT fk_users_permissions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_users_permissions_permission FOREIGN KEY (permission_id) REFERENCES `permissions` (id) ON DELETE CASCADE
);

CREATE TABLE web_origins (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  origin TEXT NOT NULL,
  client_id INTEGER NOT NULL,  
  CONSTRAINT fk_clients_web_origins FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX `idx_client_identifier` ON `clients`(`client_identifier`);
CREATE UNIQUE INDEX `idx_resource_identifier` ON `resources`(`resource_identifier`);
CREATE UNIQUE INDEX `idx_subject` ON `users`(`subject`);
CREATE UNIQUE INDEX `idx_email` ON `users`(`email`);
CREATE INDEX `idx_username` ON `users`(`username`);
CREATE INDEX `idx_given_name` ON `users`(`given_name`);
CREATE INDEX `idx_middle_name` ON `users`(`middle_name`);
CREATE INDEX `idx_family_name` ON `users`(`family_name`);
CREATE UNIQUE INDEX `idx_code_hash` ON `codes`(`code_hash`);
CREATE UNIQUE INDEX `idx_group_identifier` ON `groups`(`group_identifier`);
CREATE INDEX `idx_httpsess_expires` ON `http_sessions`(`expires_on`);
CREATE INDEX `idx_state` ON `key_pairs`(`state`);
CREATE INDEX `idx_pre_reg_email` ON `pre_registrations`(`email`);
CREATE UNIQUE INDEX `idx_refresh_token_jti` ON `refresh_tokens`(`refresh_token_jti`);
CREATE UNIQUE INDEX `idx_session_identifier` ON `user_sessions`(`session_identifier`);
CREATE UNIQUE INDEX idx_permission_identifier_resource ON permissions(permission_identifier, resource_id);

CREATE TABLE IF NOT EXISTS "settings" (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  app_name TEXT NOT NULL,
  issuer TEXT NOT NULL,
  ui_theme TEXT NOT NULL,
  password_policy INTEGER DEFAULT NULL,
  self_registration_enabled INTEGER NOT NULL,
  self_registration_requires_email_verification INTEGER NOT NULL,
  token_expiration_in_seconds INTEGER NOT NULL,
  refresh_token_offline_idle_timeout_in_seconds INTEGER NOT NULL,
  refresh_token_offline_max_lifetime_in_seconds INTEGER NOT NULL,
  user_session_idle_timeout_in_seconds INTEGER NOT NULL,
  user_session_max_lifetime_in_seconds INTEGER NOT NULL,
  include_open_id_connect_claims_in_access_token INTEGER NOT NULL,
  include_open_id_connect_claims_in_id_token INTEGER NOT NULL DEFAULT 1,
  aes_encryption_key BLOB NOT NULL,
  smtp_host TEXT,
  smtp_port INTEGER DEFAULT NULL,
  smtp_username TEXT,
  smtp_password_encrypted BLOB,
  smtp_from_name TEXT,
  smtp_from_email TEXT,
  smtp_encryption TEXT,
  smtp_enabled INTEGER NOT NULL,
  dynamic_client_registration_enabled BOOLEAN NOT NULL DEFAULT 0,
  pkce_required BOOLEAN NOT NULL DEFAULT 1,
  implicit_flow_enabled BOOLEAN NOT NULL DEFAULT 0,
  resource_owner_password_credentials_enabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE user_profile_pictures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NULL,
    updated_at DATETIME NULL,
    user_id INTEGER NOT NULL UNIQUE,
    picture BLOB NOT NULL,
    content_type TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE client_logos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NULL,
    updated_at DATETIME NULL,
    client_id INTEGER NOT NULL UNIQUE,
    logo BLOB NOT NULL,
    content_type TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
