-- Restores settings.session_authentication_key and settings.session_encryption_key, which
-- 000001 and 000002 both declare BLOB NOT NULL with no default.
--
-- Rebuilt rather than ALTERed because SQLite cannot ADD COLUMN ... NOT NULL to a populated
-- table without a DEFAULT, and the shape being restored has no default: adding one to get the
-- statement accepted would leave a column that differs from the one the up migration dropped.
-- The rebuild is the same fix 000002's own down uses for the same reason, and the column list
-- below is 000002's settings_new verbatim, which is what this table looks like at 000002.
--
-- The keys come back EMPTY. 000003's up dropped the columns, so their contents are gone and no
-- down can recover them; what a rollback restores is the shape (#268 decision 11).
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

INSERT INTO settings_new (
  id, created_at, updated_at, app_name, issuer, ui_theme, password_policy,
  self_registration_enabled, self_registration_requires_email_verification,
  token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds,
  refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds,
  user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token,
  session_authentication_key, session_encryption_key, aes_encryption_key,
  smtp_host, smtp_port, smtp_username, smtp_password_encrypted,
  smtp_from_name, smtp_from_email, smtp_encryption, smtp_enabled
)
SELECT
  id, created_at, updated_at, app_name, issuer, ui_theme, password_policy,
  self_registration_enabled, self_registration_requires_email_verification,
  token_expiration_in_seconds, refresh_token_offline_idle_timeout_in_seconds,
  refresh_token_offline_max_lifetime_in_seconds, user_session_idle_timeout_in_seconds,
  user_session_max_lifetime_in_seconds, include_open_id_connect_claims_in_access_token,
  x'', x'', aes_encryption_key,
  smtp_host, smtp_port, smtp_username, smtp_password_encrypted,
  smtp_from_name, smtp_from_email, smtp_encryption, smtp_enabled
FROM settings;

DROP TABLE settings;
ALTER TABLE settings_new RENAME TO settings;
