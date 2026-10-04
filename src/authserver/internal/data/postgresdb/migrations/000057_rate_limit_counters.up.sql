-- The shared counts of the credential-guessing rate limits (#394). See the sqlite migration of the
-- same number for why, what a row is, and the six questions. PostgreSQL compares strings
-- byte-wise, so key_hash needs no collation pin.
CREATE TABLE rate_limit_counters (
    key_hash character varying(64) NOT NULL,
    window_start timestamp(6) without time zone NOT NULL,
    hits integer NOT NULL,
    expires_at timestamp(6) without time zone NOT NULL,
    PRIMARY KEY (key_hash, window_start)
);
CREATE INDEX idx_rate_limit_counters_expires_at ON rate_limit_counters(expires_at);
