-- parity: mysql, postgres and sqlite only. SQL Server is the engine the other three are
-- converging on and needs no file: fk_refresh_tokens_user and fk_refresh_tokens_client have been
-- ON DELETE NO ACTION there since its 000011, and codes.code_challenge and code_challenge_method
-- have been nullable since its own 000007.
--
-- Two of issue #282's divergences, in one file, because both need the same rebuild.
--
-- 1. codes.code_challenge and code_challenge_method are still NOT NULL on SQLite. 000007
--    was a no-op here, justified by a comment claiming SQLite does not enforce NOT NULL;
--    it does, on every column type. CodeIssuer.CreateAuthCode leaves both sql.NullString
--    values at Valid:false when the authorization request carried no challenge, so the
--    insert sends NULL and fails. A confidential client configured for PKCE-optional
--    therefore runs the whole ceremony and gets a 500 at /auth/issue on the default
--    engine. The other three have been nullable since their own 000007.
--
-- 2. refresh_tokens.user_id and client_id are ON DELETE CASCADE here, on MySQL and on
--    PostgreSQL, and ON DELETE NO ACTION on SQL Server, which refuses the cascade
--    outright: users <- codes <- refresh_tokens(code_id) alongside
--    users <- refresh_tokens(user_id) is a multiple cascade path (Msg 1785). Parity is
--    only reachable downward. It is unobservable: DeleteUser and DeleteClient are the
--    only statements in the codebase that delete a user or a client row, and both clear
--    that row's refresh tokens first, which is why SQL Server has run this way since
--    000011 without anyone noticing.
--
-- ORDERING, and why it is not the obvious one. golang-migrate's sqlite driver runs this
-- inside a transaction, and PRAGMA foreign_keys cannot be changed inside one. So
-- DROP TABLE codes fires an implicit DELETE that CASCADEs into refresh_tokens(code_id)
-- and destroys every refresh token issued through the authorization code flow. Nothing
-- reports it: PRAGMA foreign_key_check is clean afterwards. PRAGMA defer_foreign_keys,
-- PRAGMA legacy_alter_table and PRAGMA foreign_keys = OFF were each measured and none
-- prevents it. What works is parking refresh_tokens in a constraint-free copy and
-- dropping it BEFORE codes is touched, so codes is childless when it goes.
--
-- Both tables are integer PRIMARY KEY AUTOINCREMENT, so refilling with explicit ids
-- leaves sqlite_sequence at the highest surviving id. A high-water mark above that, left
-- by deleting the newest row before this migration ran, is lost and that id becomes
-- reusable. Nothing depends on it: both ids are internal surrogates, every lookup goes
-- through code_hash or a jti, and 000011 already did exactly this to refresh_tokens.

-- 1. Park refresh_tokens. CREATE TABLE AS carries no constraints, which is the point:
--    the parked copy holds no foreign key into codes.
CREATE TABLE rt_parked AS SELECT * FROM refresh_tokens;
DROP TABLE refresh_tokens;

-- 2. Rebuild codes with both PKCE columns nullable. Every other column, both foreign keys
--    and all three indexes are reproduced as the migrated catalog reports them.
CREATE TABLE codes_new (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  code_hash TEXT NOT NULL,
  client_id INTEGER NOT NULL,
  code_challenge TEXT NULL,
  code_challenge_method TEXT NULL,
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

-- 3. Rebuild refresh_tokens. code_id keeps its cascade, which is the one the engines
--    already agree on; user_id and client_id come down to NO ACTION to meet SQL Server.
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
  CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE NO ACTION,
  CONSTRAINT fk_refresh_tokens_client FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE NO ACTION
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

-- All five indexes, idx_refresh_tokens_client_id included: 000036 added it minutes before
-- this file in the same change, and a recreate list that forgot it would silently undo it.
CREATE UNIQUE INDEX idx_refresh_token_jti ON refresh_tokens (refresh_token_jti);
CREATE INDEX idx_refresh_tokens_code_id ON refresh_tokens(code_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id);
CREATE INDEX idx_refresh_tokens_first_refresh_token_jti
    ON refresh_tokens(first_refresh_token_jti);
