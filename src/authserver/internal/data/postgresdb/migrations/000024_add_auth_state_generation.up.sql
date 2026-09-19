-- Per-user authentication generation boundary (#106). See the sqlite migration of
-- the same number for what the columns mean and why existing rows land at 0.
ALTER TABLE users ADD COLUMN auth_state_generation bigint NOT NULL DEFAULT 0;
ALTER TABLE user_sessions ADD COLUMN auth_state_generation bigint NOT NULL DEFAULT 0;
ALTER TABLE codes ADD COLUMN auth_state_generation bigint NOT NULL DEFAULT 0;
ALTER TABLE refresh_tokens ADD COLUMN auth_state_generation bigint NOT NULL DEFAULT 0;

-- PostgreSQL does not index foreign key columns automatically. 000011 already added
-- idx_refresh_tokens_user_id, so refresh_tokens.user_id is covered and the rest are not.
CREATE INDEX idx_codes_user_id ON codes(user_id);
CREATE INDEX idx_codes_session_identifier ON codes(session_identifier);
CREATE INDEX idx_refresh_tokens_code_id ON refresh_tokens(code_id);
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
