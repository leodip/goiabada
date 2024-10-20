-- 000002_v0_7.up.sql

-- Modify permissions table
DROP INDEX IF EXISTS idx_permission_identifier;
CREATE UNIQUE INDEX idx_permission_identifier_resource ON permissions(permission_identifier, resource_id);

-- Modify users table
ALTER TABLE users ADD COLUMN phone_number_country_uniqueid TEXT;
ALTER TABLE users ADD COLUMN phone_number_country_callingcode TEXT;

-- Modify user_sessions table
ALTER TABLE user_sessions ADD COLUMN level2_auth_config_has_changed INTEGER NOT NULL DEFAULT 0;

-- Modify settings table
-- SQLite doesn't support dropping columns, so we need to recreate the table
CREATE TABLE settings_new (
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
  session_authentication_key BLOB NOT NULL,
  session_encryption_key BLOB NOT NULL,
  aes_encryption_key BLOB NOT NULL,
  smtp_host TEXT,
  smtp_port INTEGER DEFAULT NULL,
  smtp_username TEXT,
  smtp_password_encrypted BLOB,
  smtp_from_name TEXT,
  smtp_from_email TEXT,
  smtp_encryption TEXT,
  smtp_enabled INTEGER NOT NULL
);

INSERT INTO settings_new SELECT 
  id, created_at, updated_at, app_name, issuer, ui_theme, password_policy,
  self_registration_enabled, self_registration_requires_email_verification,
  token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds,
  refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds,
  user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token,
  session_authentication_key, session_encryption_key, aes_encryption_key,
  smtp_host, smtp_port, smtp_username, smtp_password_encrypted,
  smtp_from_name, smtp_from_email, smtp_encryption, smtp_enabled
FROM settings;

DROP TABLE settings;
ALTER TABLE settings_new RENAME TO settings;
