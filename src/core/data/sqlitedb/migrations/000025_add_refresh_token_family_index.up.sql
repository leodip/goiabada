-- Index the rotation family identifier (#128).
--
-- Replay containment revokes every live member of one rotation family in a single
-- statement (WHERE first_refresh_token_jti = ? AND revoked = false). That sits on a
-- request-driven path which a client holding a revoked token can repeat at will, so
-- without an index it forces a full scan of a table whose size grows with refresh
-- frequency and token lifetime. #128 also stops the cleanup sweep from deleting rows
-- merely for being revoked, which makes the table larger still.
--
-- Non-unique deliberately: every descendant of one rotation chain carries the same
-- value, so a UNIQUE index here would reject the second member of every family and
-- break rotation outright.
CREATE INDEX idx_refresh_tokens_first_refresh_token_jti
    ON refresh_tokens(first_refresh_token_jti);
