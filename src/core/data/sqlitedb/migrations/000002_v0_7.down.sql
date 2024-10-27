-- 000002_v0_7.down.sql

-- Reverse modifications to permissions table
DROP INDEX IF EXISTS idx_permission_identifier_resource;
CREATE UNIQUE INDEX idx_permission_identifier ON permissions(permission_identifier);

-- Reverse modifications to users table
-- SQLite doesn't support dropping columns, so we need to recreate the table
CREATE TABLE users_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  enabled INTEGER NOT NULL,
  subject TEXT NOT NULL,
  username TEXT NOT NULL,
  given_name TEXT,
  middle_name TEXT,
  family_name TEXT,
  nickname TEXT,
  website TEXT,
  gender TEXT,
  email TEXT,
  email_verified INTEGER NOT NULL,
  email_verification_code_encrypted BLOB,
  email_verification_code_issued_at DATETIME,
  zone_info_country_name TEXT,
  zone_info TEXT,
  locale TEXT,
  birth_date DATETIME,
  phone_number TEXT,
  phone_number_verified INTEGER NOT NULL,
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
  otp_enabled INTEGER NOT NULL,
  forgot_password_code_encrypted BLOB,
  forgot_password_code_issued_at DATETIME
);

INSERT INTO users_new SELECT 
  id, created_at, updated_at, enabled, subject, username, given_name, middle_name,
  family_name, nickname, website, gender, email, email_verified,
  email_verification_code_encrypted, email_verification_code_issued_at,
  zone_info_country_name, zone_info, locale, birth_date, phone_number,
  phone_number_verified, phone_number_verification_code_encrypted,
  phone_number_verification_code_issued_at, address_line1, address_line2,
  address_locality, address_region, address_postal_code, address_country,
  password_hash, otp_secret, otp_enabled, forgot_password_code_encrypted,
  forgot_password_code_issued_at
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- Recreate indexes for users table
CREATE UNIQUE INDEX idx_subject ON users(subject);
CREATE UNIQUE INDEX idx_email ON users(email);
CREATE INDEX idx_username ON users(username);
CREATE INDEX idx_given_name ON users(given_name);
CREATE INDEX idx_middle_name ON users(middle_name);
CREATE INDEX idx_family_name ON users(family_name);

-- Reverse modifications to user_sessions table
-- SQLite doesn't support dropping columns, so we need to recreate the table
CREATE TABLE user_sessions_new (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  session_identifier TEXT NOT NULL,
  started DATETIME NOT NULL,
  last_accessed DATETIME NOT NULL,
  auth_methods TEXT NOT NULL,
  acr_level TEXT NOT NULL,
  auth_time DATETIME NOT NULL,
  ip_address TEXT NOT NULL,
  device_name TEXT NOT NULL,
  device_type TEXT NOT NULL,
  device_os TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

INSERT INTO user_sessions_new SELECT 
  id, created_at, updated_at, session_identifier, started, last_accessed,
  auth_methods, acr_level, auth_time, ip_address, device_name, device_type,
  device_os, user_id
FROM user_sessions;

DROP TABLE user_sessions;
ALTER TABLE user_sessions_new RENAME TO user_sessions;

CREATE UNIQUE INDEX idx_session_identifier ON user_sessions(session_identifier);

-- Reverse modifications to settings table
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
  smtp_enabled INTEGER NOT NULL,
  sms_provider TEXT,
  sms_config_encrypted BLOB
);

INSERT INTO settings_new SELECT 
  id, created_at, updated_at, app_name, issuer, ui_theme, password_policy,
  self_registration_enabled, self_registration_requires_email_verification,
  token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds,
  refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds,
  user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token,
  session_authentication_key, session_encryption_key, aes_encryption_key,
  smtp_host, smtp_port, smtp_username, smtp_password_encrypted,
  smtp_from_name, smtp_from_email, smtp_encryption, smtp_enabled,
  NULL, NULL
FROM settings;

DROP TABLE settings;
ALTER TABLE settings_new RENAME TO settings;
