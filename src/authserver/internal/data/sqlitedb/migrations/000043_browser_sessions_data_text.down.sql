-- parity: sqlite only, matching the up migration.
--
-- Restores the `longtext` declaration 000035 wrote, so that rolling back reaches the shape
-- the previous version's golden file records. It is the wrong spelling on this engine, which
-- is the whole point of the up migration; a down migration restores the previous state rather
-- than an improved one.
--
-- Same rebuild, same reason it is safe: nothing holds a foreign key onto browser_sessions, so
-- the implicit DELETE behind DROP TABLE has nowhere to cascade. Both indexes are recreated
-- because DROP TABLE takes them with it.
CREATE TABLE browser_sessions_old (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    owner TEXT NOT NULL,
    session_id_hash TEXT NOT NULL,
    data longtext,
    last_accessed DATETIME NOT NULL,
    expires_at DATETIME NOT NULL
);
INSERT INTO browser_sessions_old (id, created_at, updated_at, owner, session_id_hash, data, last_accessed, expires_at)
SELECT id, created_at, updated_at, owner, session_id_hash, data, last_accessed, expires_at FROM browser_sessions;
DROP TABLE browser_sessions;
ALTER TABLE browser_sessions_old RENAME TO browser_sessions;
CREATE UNIQUE INDEX idx_browser_sessions_owner_hash ON browser_sessions(owner, session_id_hash);
CREATE INDEX idx_browser_sessions_expires_at ON browser_sessions(expires_at);
