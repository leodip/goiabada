

CREATE TABLE clients (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  client_identifier TEXT NOT NULL,
  client_secret_encrypted BLOB,
  `description` TEXT DEFAULT NULL,
  `enabled` BOOLEAN NOT NULL,
  consent_required BOOLEAN NOT NULL,
  is_public BOOLEAN NOT NULL,
  authorization_code_enabled BOOLEAN NOT NULL,
  client_credentials_enabled BOOLEAN NOT NULL,
  token_expiration_in_seconds int NOT NULL,
  refresh_token_offline_idle_timeout_in_seconds int NOT NULL,
  refresh_token_offline_max_lifetime_in_seconds int NOT NULL,
  include_open_id_connect_claims_in_access_token TEXT NOT NULL,
  default_acr_level TEXT NOT NULL
);


CREATE TABLE resources (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  resource_identifier TEXT NOT NULL,
  `description` TEXT DEFAULT NULL  
);


CREATE TABLE permissions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  permission_identifier TEXT NOT NULL,
  `description` TEXT DEFAULT NULL,
  resource_id INTEGER NOT NULL,      
  CONSTRAINT fk_permissions_resource FOREIGN KEY (resource_id) REFERENCES resources (id) ON DELETE CASCADE
);


CREATE TABLE clients_permissions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  client_id INTEGER NOT NULL,  
  permission_id INTEGER NOT NULL,      
  CONSTRAINT fk_clients_permissions_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
  CONSTRAINT fk_clients_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);


CREATE TABLE users (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  `enabled` BOOLEAN NOT NULL,
  `subject` TEXT NOT NULL,
  `username` TEXT NOT NULL,
  given_name TEXT DEFAULT NULL,
  middle_name TEXT DEFAULT NULL,
  family_name TEXT DEFAULT NULL,
  nickname TEXT DEFAULT NULL,
  website TEXT DEFAULT NULL,
  gender TEXT DEFAULT NULL,
  email TEXT DEFAULT NULL,
  email_verified BOOLEAN NOT NULL,
  email_verification_code_encrypted BLOB,
  email_verification_code_issued_at DATETIME DEFAULT NULL,
  zone_info_country_name TEXT DEFAULT NULL,
  zone_info TEXT DEFAULT NULL,
  locale TEXT DEFAULT NULL,
  birth_date DATETIME DEFAULT NULL,
  phone_number TEXT DEFAULT NULL,
  phone_number_verified BOOLEAN NOT NULL,
  phone_number_verification_code_encrypted BLOB,
  phone_number_verification_code_issued_at DATETIME DEFAULT NULL,
  address_line1 TEXT DEFAULT NULL,
  address_line2 TEXT DEFAULT NULL,
  address_locality TEXT DEFAULT NULL,
  address_region TEXT DEFAULT NULL,
  address_postal_code TEXT DEFAULT NULL,
  address_country TEXT DEFAULT NULL,
  password_hash TEXT NOT NULL,
  otp_secret TEXT DEFAULT NULL,
  otp_enabled BOOLEAN NOT NULL,
  forgot_password_code_encrypted BLOB,
  forgot_password_code_issued_at DATETIME DEFAULT NULL
);


CREATE TABLE codes (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
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
  used BOOLEAN NOT NULL,  
  CONSTRAINT fk_codes_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
  CONSTRAINT fk_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);


CREATE TABLE groups (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  group_identifier TEXT NOT NULL,
  `description` TEXT DEFAULT NULL,
  include_in_id_token BOOLEAN NOT NULL,
  include_in_access_token BOOLEAN NOT NULL  
);


CREATE TABLE group_attributes (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  `key` TEXT NOT NULL,
  `value` TEXT NOT NULL,
  include_in_id_token BOOLEAN NOT NULL,
  include_in_access_token BOOLEAN NOT NULL,
  group_id INTEGER NOT NULL,  
  CONSTRAINT fk_groups_attributes FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE
);


CREATE TABLE groups_permissions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  group_id INTEGER NOT NULL,
  permission_id INTEGER NOT NULL,    
  CONSTRAINT fk_groups_permissions_group FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
  CONSTRAINT fk_groups_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);


CREATE TABLE http_sessions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  `data` longtext,  
  expires_on DATETIME DEFAULT NULL  
);


CREATE TABLE key_pairs (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
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
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  email TEXT DEFAULT NULL,
  password_hash TEXT NOT NULL,
  verification_code_encrypted BLOB,
  verification_code_issued_at DATETIME DEFAULT NULL
);


CREATE TABLE redirect_uris (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  uri TEXT NOT NULL,
  client_id INTEGER NOT NULL,  
  CONSTRAINT fk_clients_redirect_uris FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);


CREATE TABLE refresh_tokens (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  code_id INTEGER NOT NULL,
  refresh_token_jti TEXT NOT NULL,
  previous_refresh_token_jti TEXT NOT NULL,
  first_refresh_token_jti TEXT NOT NULL,
  session_identifier TEXT NOT NULL,
  refresh_token_type TEXT NOT NULL,
  scope TEXT NOT NULL,
  issued_at DATETIME DEFAULT NULL,
  expires_at DATETIME DEFAULT NULL,
  max_lifetime DATETIME DEFAULT NULL,
  revoked BOOLEAN NOT NULL,    
  CONSTRAINT fk_refresh_tokens_code FOREIGN KEY (code_id) REFERENCES codes (id) ON DELETE CASCADE
);


CREATE TABLE settings (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  app_name TEXT NOT NULL,
  issuer TEXT NOT NULL,
  ui_theme TEXT NOT NULL,
  password_policy int DEFAULT NULL,
  self_registration_enabled BOOLEAN NOT NULL,
  self_registration_requires_email_verification BOOLEAN NOT NULL,
  token_expiration_in_seconds int NOT NULL,
  refresh_token_offline_idle_timeout_in_seconds int NOT NULL,
  refresh_token_offline_max_lifetime_in_seconds int NOT NULL,
  user_session_idle_timeout_in_seconds int NOT NULL,
  user_session_max_lifetime_in_seconds int NOT NULL,
  include_open_id_connect_claims_in_access_token BOOLEAN NOT NULL,
  session_authentication_key BLOB NOT NULL,
  session_encryption_key BLOB NOT NULL,
  aes_encryption_key BLOB NOT NULL,
  smtp_host TEXT DEFAULT NULL,
  smtp_port int DEFAULT NULL,
  smtp_username TEXT DEFAULT NULL,
  smtp_password_encrypted BLOB,
  smtp_from_name TEXT DEFAULT NULL,
  smtp_from_email TEXT DEFAULT NULL,
  smtp_encryption TEXT DEFAULT NULL,
  smtp_enabled BOOLEAN NOT NULL,
  sms_provider TEXT DEFAULT NULL,
  sms_config_encrypted BLOB
);



CREATE TABLE user_attributes (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  `key` TEXT NOT NULL,
  `value` TEXT NOT NULL,
  include_in_id_token BOOLEAN NOT NULL,
  include_in_access_token BOOLEAN NOT NULL,
  user_id INTEGER NOT NULL,    
  CONSTRAINT fk_users_attributes FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);


CREATE TABLE user_consents (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  user_id INTEGER NOT NULL,
  client_id INTEGER NOT NULL,
  scope TEXT NOT NULL,
  granted_at DATETIME DEFAULT NULL,  
  CONSTRAINT fk_user_consents_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
  CONSTRAINT fk_user_consents_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);


CREATE TABLE user_sessions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
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
  user_id INTEGER NOT NULL,  
  CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
); 


CREATE TABLE user_session_clients (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  user_session_id INTEGER NOT NULL,
  client_id INTEGER NOT NULL,
  `started` DATETIME NOT NULL,
  last_accessed DATETIME NOT NULL,  
  CONSTRAINT fk_user_sessions_clients FOREIGN KEY (user_session_id) REFERENCES user_sessions (id) ON DELETE CASCADE,
  CONSTRAINT fk_user_session_clients_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);


CREATE TABLE users_groups (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  group_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,  
  CONSTRAINT fk_users_groups_group FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE,
  CONSTRAINT fk_users_groups_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);



CREATE TABLE users_permissions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  updated_at DATETIME DEFAULT NULL,
  user_id INTEGER NOT NULL,
  permission_id INTEGER NOT NULL,  
  CONSTRAINT fk_users_permissions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_users_permissions_permission FOREIGN KEY (permission_id) REFERENCES `permissions` (id) ON DELETE CASCADE
);


CREATE TABLE web_origins (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME DEFAULT NULL,
  origin TEXT NOT NULL,
  client_id INTEGER NOT NULL,  
  CONSTRAINT fk_clients_web_origins FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX `idx_client_identifier` ON `clients`(`client_identifier`);
CREATE UNIQUE INDEX `idx_resource_identifier` ON `resources`(`resource_identifier`);
CREATE UNIQUE INDEX `idx_permission_identifier` ON `permissions`(`permission_identifier`);
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

