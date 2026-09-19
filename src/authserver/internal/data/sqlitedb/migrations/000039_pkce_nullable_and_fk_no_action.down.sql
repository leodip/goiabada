-- The mirror of 000039's up: codes.code_challenge and code_challenge_method go back to
-- NOT NULL, and refresh_tokens.user_id and client_id back to ON DELETE CASCADE.
--
-- The same parking ordering is required for the same reason: DROP TABLE codes inside
-- golang-migrate's transaction cascades into refresh_tokens(code_id) and silently
-- destroys every auth-code-issued token, and PRAGMA foreign_keys cannot be turned off
-- inside a transaction. So refresh_tokens is parked and dropped before codes is touched.
--
-- NULL becomes '' on the way back. That conversion is lossless for every reader: all
-- three tests in ValidateTokenRequest's PKCE downgrade mitigation already treat an empty
-- string and NULL alike, reading .Valid && != "" or !.Valid || == "", and the code says
-- so. Rows written by a challenge-less ceremony while 000039 was applied therefore keep
-- working rather than blocking this migration.

CREATE TABLE rt_parked AS SELECT * FROM refresh_tokens;
DROP TABLE refresh_tokens;

UPDATE codes SET code_challenge = '' WHERE code_challenge IS NULL;
UPDATE codes SET code_challenge_method = '' WHERE code_challenge_method IS NULL;

CREATE TABLE codes_new (
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
  auth_state_generation INTEGER NOT NULL DEFAULT 0,
  revoked numeric NOT NULL DEFAULT 0,
  CONSTRAINT fk_codes_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE,
  CONSTRAINT fk_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

INSERT INTO codes_new (
  `id`, created_at, updated_at, code_hash, client_id, code_challenge, code_challenge_method,
  scope, `state`, nonce, redirect_uri, user_id, ip_address, user_agent, response_mode,
  authenticated_at, session_identifier, acr_level, auth_methods, used, auth_state_generation,
  revoked)
SELECT
  `id`, created_at, updated_at, code_hash, client_id, code_challenge, code_challenge_method,
  scope, `state`, nonce, redirect_uri, user_id, ip_address, user_agent, response_mode,
  authenticated_at, session_identifier, acr_level, auth_methods, used, auth_state_generation,
  revoked
FROM codes;

DROP TABLE codes;
ALTER TABLE codes_new RENAME TO codes;

CREATE UNIQUE INDEX `idx_code_hash` ON `codes`(`code_hash`);
CREATE INDEX idx_codes_session_identifier ON codes(session_identifier);
CREATE INDEX idx_codes_user_id ON codes(user_id);

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
  auth_state_generation INTEGER NOT NULL DEFAULT 0,
  CONSTRAINT fk_refresh_tokens_code FOREIGN KEY (code_id) REFERENCES codes (id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_tokens_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);

INSERT INTO refresh_tokens (
  `id`, created_at, updated_at, code_id, user_id, client_id, refresh_token_jti,
  previous_refresh_token_jti, first_refresh_token_jti, session_identifier, refresh_token_type,
  scope, issued_at, expires_at, max_lifetime, revoked, auth_state_generation)
SELECT
  `id`, created_at, updated_at, code_id, user_id, client_id, refresh_token_jti,
  previous_refresh_token_jti, first_refresh_token_jti, session_identifier, refresh_token_type,
  scope, issued_at, expires_at, max_lifetime, revoked, auth_state_generation
FROM rt_parked;

DROP TABLE rt_parked;

CREATE UNIQUE INDEX idx_refresh_token_jti ON refresh_tokens (refresh_token_jti);
CREATE INDEX idx_refresh_tokens_code_id ON refresh_tokens(code_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id);
CREATE INDEX idx_refresh_tokens_first_refresh_token_jti
    ON refresh_tokens(first_refresh_token_jti);
