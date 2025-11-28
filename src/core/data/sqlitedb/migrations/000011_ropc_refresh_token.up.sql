-- Add user_id and client_id columns to refresh_tokens for ROPC flow
-- These allow refresh tokens to be created without a Code entity

-- SQLite doesn't support ALTER COLUMN or modifying constraints directly
-- We need to recreate the table to make code_id nullable

-- Step 1: Create new table with updated schema
CREATE TABLE refresh_tokens_new (
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

-- Step 2: Copy data from old table
INSERT INTO refresh_tokens_new (
  id, created_at, updated_at, code_id, user_id, client_id,
  refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti,
  session_identifier, refresh_token_type, scope, issued_at, expires_at,
  max_lifetime, revoked
)
SELECT
  id, created_at, updated_at, code_id, NULL, NULL,
  refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti,
  session_identifier, refresh_token_type, scope, issued_at, expires_at,
  max_lifetime, revoked
FROM refresh_tokens;

-- Step 3: Drop old table
DROP TABLE refresh_tokens;

-- Step 4: Rename new table
ALTER TABLE refresh_tokens_new RENAME TO refresh_tokens;

-- Step 5: Recreate index
CREATE UNIQUE INDEX idx_refresh_token_jti ON refresh_tokens (refresh_token_jti);
