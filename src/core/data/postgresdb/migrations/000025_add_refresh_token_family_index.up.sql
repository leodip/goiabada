-- Index the rotation family identifier (#128). See the sqlite migration of the same
-- number for what containment queries and why the index must not be UNIQUE.
CREATE INDEX idx_refresh_tokens_first_refresh_token_jti
    ON refresh_tokens(first_refresh_token_jti);
