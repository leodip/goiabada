-- Revert: Remove user_id and client_id columns, make code_id NOT NULL again

-- Step 1: Create table with original schema
CREATE TABLE refresh_tokens_old (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  code_id INTEGER NOT NULL,
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
  CONSTRAINT fk_refresh_tokens_code FOREIGN KEY (code_id) REFERENCES codes (id) ON DELETE CASCADE
);

-- Step 2: Copy data (only rows with code_id, ROPC tokens will be lost)
INSERT INTO refresh_tokens_old (
  id, created_at, updated_at, code_id,
  refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti,
  session_identifier, refresh_token_type, scope, issued_at, expires_at,
  max_lifetime, revoked
)
SELECT
  id, created_at, updated_at, code_id,
  refresh_token_jti, previous_refresh_token_jti, first_refresh_token_jti,
  session_identifier, refresh_token_type, scope, issued_at, expires_at,
  max_lifetime, revoked
FROM refresh_tokens
WHERE code_id IS NOT NULL;

-- Step 3: Drop new table
DROP TABLE refresh_tokens;

-- Step 4: Rename old table back
ALTER TABLE refresh_tokens_old RENAME TO refresh_tokens;

-- Step 5: Recreate index
CREATE UNIQUE INDEX idx_refresh_token_jti ON refresh_tokens (refresh_token_jti);
