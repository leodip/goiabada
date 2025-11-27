-- 000001_initial_create.up.sql

CREATE TABLE clients (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  client_identifier VARCHAR(40) NOT NULL,
  client_secret_encrypted BYTEA,
  description VARCHAR(128),
  enabled BOOLEAN NOT NULL,
  consent_required BOOLEAN NOT NULL,
  is_public BOOLEAN NOT NULL,
  authorization_code_enabled BOOLEAN NOT NULL,
  client_credentials_enabled BOOLEAN NOT NULL,
  token_expiration_in_seconds INTEGER NOT NULL,
  refresh_token_offline_idle_timeout_in_seconds INTEGER NOT NULL,
  refresh_token_offline_max_lifetime_in_seconds INTEGER NOT NULL,
  include_open_id_connect_claims_in_access_token VARCHAR(16) NOT NULL,
  default_acr_level VARCHAR(128) NOT NULL
);

CREATE TABLE resources (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  resource_identifier VARCHAR(40) NOT NULL,
  description VARCHAR(128)
);

CREATE TABLE permissions (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  permission_identifier VARCHAR(40) NOT NULL,
  description VARCHAR(128),
  resource_id BIGINT NOT NULL,
  CONSTRAINT fk_permissions_resource FOREIGN KEY (resource_id) REFERENCES resources (id) ON DELETE CASCADE
);

CREATE TABLE clients_permissions (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  client_id BIGINT NOT NULL,
  permission_id BIGINT NOT NULL,
  CONSTRAINT fk_clients_permissions_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
  CONSTRAINT fk_clients_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  enabled BOOLEAN NOT NULL,
  subject VARCHAR(64) NOT NULL,
  username VARCHAR(32) NOT NULL,
  given_name VARCHAR(64),
  middle_name VARCHAR(64),
  family_name VARCHAR(64),
  nickname VARCHAR(64),
  website VARCHAR(128),
  gender VARCHAR(16),
  email VARCHAR(64),
  email_verified BOOLEAN NOT NULL,
  email_verification_code_encrypted BYTEA,
  email_verification_code_issued_at TIMESTAMP(6),
  zone_info_country_name VARCHAR(128),
  zone_info VARCHAR(128),
  locale VARCHAR(32),
  birth_date TIMESTAMP(6),
  phone_number VARCHAR(32),
  phone_number_country_uniqueid VARCHAR(16),
  phone_number_country_callingcode VARCHAR(16),
  phone_number_verified BOOLEAN NOT NULL,
  phone_number_verification_code_encrypted BYTEA,
  phone_number_verification_code_issued_at TIMESTAMP(6),
  address_line1 VARCHAR(64),
  address_line2 VARCHAR(64),
  address_locality VARCHAR(64),
  address_region VARCHAR(64),
  address_postal_code VARCHAR(32),
  address_country VARCHAR(32),
  password_hash VARCHAR(64) NOT NULL,
  otp_secret VARCHAR(64),
  otp_enabled BOOLEAN NOT NULL,
  forgot_password_code_encrypted BYTEA,
  forgot_password_code_issued_at TIMESTAMP(6)
);

CREATE TABLE codes (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  code_hash VARCHAR(64) NOT NULL,
  client_id BIGINT NOT NULL,
  code_challenge VARCHAR(256) NOT NULL,
  code_challenge_method VARCHAR(10) NOT NULL,
  scope VARCHAR(512) NOT NULL,
  state VARCHAR(512) NOT NULL,
  nonce VARCHAR(512) NOT NULL,
  redirect_uri VARCHAR(256) NOT NULL,
  user_id BIGINT NOT NULL,
  ip_address VARCHAR(64) NOT NULL,
  user_agent VARCHAR(512) NOT NULL,
  response_mode VARCHAR(16) NOT NULL,
  authenticated_at TIMESTAMP(6) NOT NULL,
  session_identifier VARCHAR(64) NOT NULL,
  acr_level VARCHAR(128) NOT NULL,
  auth_methods VARCHAR(64) NOT NULL,
  used BOOLEAN NOT NULL,
  CONSTRAINT fk_codes_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
  CONSTRAINT fk_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE groups (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  group_identifier VARCHAR(40) NOT NULL,
  description VARCHAR(128),
  include_in_id_token BOOLEAN NOT NULL,
  include_in_access_token BOOLEAN NOT NULL
);

CREATE TABLE group_attributes (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  key VARCHAR(32) NOT NULL,
  value VARCHAR(256) NOT NULL,
  include_in_id_token BOOLEAN NOT NULL,
  include_in_access_token BOOLEAN NOT NULL,
  group_id BIGINT NOT NULL,
  CONSTRAINT fk_groups_attributes FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE
);

CREATE TABLE groups_permissions (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  group_id BIGINT NOT NULL,
  permission_id BIGINT NOT NULL,
  CONSTRAINT fk_groups_permissions_group FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
  CONSTRAINT fk_groups_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE TABLE http_sessions (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  data TEXT,
  expires_on TIMESTAMP(6)
);

CREATE TABLE key_pairs (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  state VARCHAR(191) NOT NULL,
  key_identifier VARCHAR(64) NOT NULL,
  type VARCHAR(16) NOT NULL,
  algorithm VARCHAR(16) NOT NULL,
  private_key_pem BYTEA,
  public_key_pem BYTEA,
  public_key_asn1_der BYTEA,
  public_key_jwk BYTEA
);

CREATE TABLE pre_registrations (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  email VARCHAR(64),
  password_hash VARCHAR(64) NOT NULL,
  verification_code_encrypted BYTEA,
  verification_code_issued_at TIMESTAMP(6)
);

CREATE TABLE redirect_uris (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  uri VARCHAR(256) NOT NULL,
  client_id BIGINT NOT NULL,
  CONSTRAINT fk_clients_redirect_uris FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

CREATE TABLE refresh_tokens (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  code_id BIGINT NOT NULL,
  refresh_token_jti VARCHAR(64) NOT NULL,
  previous_refresh_token_jti VARCHAR(64) NOT NULL,
  first_refresh_token_jti VARCHAR(64) NOT NULL,
  session_identifier VARCHAR(64) NOT NULL,
  refresh_token_type VARCHAR(16) NOT NULL,
  scope VARCHAR(512) NOT NULL,
  issued_at TIMESTAMP(6),
  expires_at TIMESTAMP(6),
  max_lifetime TIMESTAMP(6),
  revoked BOOLEAN NOT NULL,
  CONSTRAINT fk_refresh_tokens_code FOREIGN KEY (code_id) REFERENCES codes (id) ON DELETE CASCADE
);

CREATE TABLE settings (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  app_name VARCHAR(32) NOT NULL,
  issuer VARCHAR(64) NOT NULL,
  ui_theme VARCHAR(32) NOT NULL,
  password_policy INTEGER,
  self_registration_enabled BOOLEAN NOT NULL,
  self_registration_requires_email_verification BOOLEAN NOT NULL,
  token_expiration_in_seconds INTEGER NOT NULL,
  refresh_token_offline_idle_timeout_in_seconds INTEGER NOT NULL,
  refresh_token_offline_max_lifetime_in_seconds INTEGER NOT NULL,
  user_session_idle_timeout_in_seconds INTEGER NOT NULL,
  user_session_max_lifetime_in_seconds INTEGER NOT NULL,
  include_open_id_connect_claims_in_access_token BOOLEAN NOT NULL,
  session_authentication_key BYTEA NOT NULL,
  session_encryption_key BYTEA NOT NULL,
  aes_encryption_key BYTEA NOT NULL,
  smtp_host VARCHAR(128),
  smtp_port INTEGER,
  smtp_username VARCHAR(64),
  smtp_password_encrypted BYTEA,
  smtp_from_name VARCHAR(64),
  smtp_from_email VARCHAR(64),
  smtp_encryption VARCHAR(16),
  smtp_enabled BOOLEAN NOT NULL
);

CREATE TABLE user_attributes (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  key VARCHAR(32) NOT NULL,
  value VARCHAR(256) NOT NULL,
  include_in_id_token BOOLEAN NOT NULL,
  include_in_access_token BOOLEAN NOT NULL,
  user_id BIGINT NOT NULL,
  CONSTRAINT fk_users_attributes FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE user_consents (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  user_id BIGINT NOT NULL,
  client_id BIGINT NOT NULL,
  scope VARCHAR(512) NOT NULL,
  granted_at TIMESTAMP(6),
  CONSTRAINT fk_user_consents_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
  CONSTRAINT fk_user_consents_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE user_sessions (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  session_identifier VARCHAR(64) NOT NULL,
  started TIMESTAMP(6) NOT NULL,
  last_accessed TIMESTAMP(6) NOT NULL,
  auth_methods VARCHAR(64) NOT NULL,
  acr_level VARCHAR(128) NOT NULL,
  auth_time TIMESTAMP(6) NOT NULL,
  ip_address VARCHAR(512) NOT NULL,
  device_name VARCHAR(256) NOT NULL,
  device_type VARCHAR(32) NOT NULL,
  device_os VARCHAR(64) NOT NULL,
  level2_auth_config_has_changed BOOLEAN NOT NULL,
  user_id BIGINT NOT NULL,
  CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE user_session_clients (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  user_session_id BIGINT NOT NULL,
  client_id BIGINT NOT NULL,
  started TIMESTAMP(6) NOT NULL,
  last_accessed TIMESTAMP(6) NOT NULL,
  CONSTRAINT fk_user_sessions_clients FOREIGN KEY (user_session_id) REFERENCES user_sessions (id) ON DELETE CASCADE,
  CONSTRAINT fk_user_session_clients_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

CREATE TABLE users_groups (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  group_id BIGINT NOT NULL,
  user_id BIGINT NOT NULL,
  CONSTRAINT fk_users_groups_group FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
  CONSTRAINT fk_users_groups_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE users_permissions (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  user_id BIGINT NOT NULL,
  permission_id BIGINT NOT NULL,
  CONSTRAINT fk_users_permissions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_users_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);

CREATE TABLE web_origins (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  origin VARCHAR(256) NOT NULL,
  client_id BIGINT NOT NULL,
  CONSTRAINT fk_clients_web_origins FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_client_identifier ON clients(client_identifier);
CREATE UNIQUE INDEX idx_resource_identifier ON resources(resource_identifier);
CREATE UNIQUE INDEX idx_permission_identifier_resource ON permissions(permission_identifier, resource_id);
CREATE UNIQUE INDEX idx_subject ON users(subject);
CREATE UNIQUE INDEX idx_email ON users(email);

CREATE INDEX idx_username ON users(username);
CREATE INDEX idx_given_name ON users(given_name);
CREATE INDEX idx_middle_name ON users(middle_name);
CREATE INDEX idx_family_name ON users(family_name);

CREATE UNIQUE INDEX idx_code_hash ON codes(code_hash);
CREATE UNIQUE INDEX idx_group_identifier ON groups(group_identifier);

CREATE INDEX idx_httpsess_expires ON http_sessions(expires_on);
CREATE INDEX idx_state ON key_pairs(state);
CREATE INDEX idx_pre_reg_email ON pre_registrations(email);

CREATE UNIQUE INDEX idx_refresh_token_jti ON refresh_tokens(refresh_token_jti);
CREATE UNIQUE INDEX idx_session_identifier ON user_sessions(session_identifier);

-- end