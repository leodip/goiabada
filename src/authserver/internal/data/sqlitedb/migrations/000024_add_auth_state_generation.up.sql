-- Per-user authentication generation boundary (#106).
--
-- Credentials authenticated under generation N cannot create or use authentication
-- state after the user advances to N+1. The column on users is the authoritative
-- counter; the copies on user_sessions, codes and refresh_tokens record which
-- generation each piece of authentication state was created under.
--
-- Existing rows land at 0, which is deliberate: an access token issued before this
-- migration carries no generation claim and is read as 0, so it keeps working until
-- that user's generation first advances.
ALTER TABLE users ADD COLUMN auth_state_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_sessions ADD COLUMN auth_state_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE codes ADD COLUMN auth_state_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE refresh_tokens ADD COLUMN auth_state_generation INTEGER NOT NULL DEFAULT 0;

-- Indexes for the user-scoped revocation sweep. SQLite has none of these: it does
-- not index foreign key columns automatically, and its migration 000011 rebuilt
-- refresh_tokens restoring only idx_refresh_token_jti.
CREATE INDEX idx_codes_user_id ON codes(user_id);
CREATE INDEX idx_codes_session_identifier ON codes(session_identifier);
CREATE INDEX idx_refresh_tokens_code_id ON refresh_tokens(code_id);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
