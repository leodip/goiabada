-- A user's recovery codes (#257 decisions 2 and 3). See the sqlite migration of the same number for
-- why, for the six questions and for what the index serves. PostgreSQL compares strings byte-wise,
-- so the hash needs no collation pin.
CREATE TABLE user_recovery_codes (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    code_hash character varying(64) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL,
    used_at TIMESTAMP(6) NULL,
    CONSTRAINT fk_user_recovery_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_user_recovery_codes_user_code_hash ON user_recovery_codes(user_id, code_hash);
