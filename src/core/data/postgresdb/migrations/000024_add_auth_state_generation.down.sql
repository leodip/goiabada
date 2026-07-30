DROP INDEX idx_user_sessions_user_id;
DROP INDEX idx_refresh_tokens_code_id;
DROP INDEX idx_codes_session_identifier;
DROP INDEX idx_codes_user_id;

ALTER TABLE refresh_tokens DROP COLUMN auth_state_generation;
ALTER TABLE codes DROP COLUMN auth_state_generation;
ALTER TABLE user_sessions DROP COLUMN auth_state_generation;
ALTER TABLE users DROP COLUMN auth_state_generation;
