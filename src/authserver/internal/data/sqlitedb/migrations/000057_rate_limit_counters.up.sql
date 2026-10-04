-- The shared counts of the credential-guessing rate limits (#394 decisions 1 to 3).
--
-- A failures-only tier counted in each process's memory gives every replica its own budget, so N
-- replicas multiply the account-wide ceiling of 100 failed passwords by N and every rollout
-- refills it. On PostgreSQL, MySQL and SQL Server those tiers count here instead, one budget for
-- the whole deployment. SQLite cannot have a second replica and keeps counting in memory, so in
-- production this table stays empty on SQLite; it exists on all four engines so the schema and
-- the data tier stay one.
--
-- One row is one tier's key in one window. key_hash is the lowercase hex SHA-256 of the tier name
-- and the key, never the key: the key is an email address, an IP block or a user id read off an
-- unauthenticated request, and the table only needs to count it. window_start is the start of
-- the window the hits belong to, aligned to the Unix epoch so every pod places a request in the
-- same window. hits is the charges taken there: a reservation is charged before the credential is
-- checked and refunded when it was right, so hits counts failures and checks in flight. A rate
-- reads the current window and the previous one, so a row is no use two windows after it began,
-- which is expires_at.
--
-- The six questions (reference/migrations.md 6): (1) all four engines. (2) key_hash is a fixed 64
-- hex characters, pinned case-sensitive where the engine needs a pin. (3) The data layer compares
-- the key_hash it reads back with the one it asked for in Go. (4) The primary key is
-- (key_hash, window_start), the one row a reservation increments and a refund decrements; the
-- plain index on expires_at serves the sweep, which deletes on that column alone. (5) No existing
-- row changes meaning: the table is new and starts empty. (6) Each schema.golden gains the table.
CREATE TABLE rate_limit_counters (
    key_hash TEXT NOT NULL,
    window_start DATETIME NOT NULL,
    hits INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    PRIMARY KEY (key_hash, window_start)
);
CREATE INDEX idx_rate_limit_counters_expires_at ON rate_limit_counters(expires_at);
