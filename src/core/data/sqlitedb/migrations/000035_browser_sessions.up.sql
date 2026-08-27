-- The browser session moves out of the cookie and into a row (#266).
--
-- Until now the whole of session.Values was gob-encoded, encrypted and split across up
-- to 50 cookies, so an ordinary sign-in put 2.6 KB in the browser's Cookie: request
-- header and the admin console's put its entire access, id and refresh token set there,
-- which is a size no deployment could promise. The cookie now carries a signed, opaque
-- 64-character identifier and nothing else, at a fixed size, and this table holds the
-- state it names.
--
-- The table is browser_sessions and NOT http_sessions, which is what the earlier
-- server-side store removed in migration 000023 called its table. That migration's DOWN
-- recreates http_sessions with different columns, so a deployment that had ever rolled
-- back to it would meet a table of that name with the wrong shape.
--
-- session_id_hash holds an unsalted SHA-256 hex digest of the identifier and never the
-- identifier itself, the shape migration 000028 established for reset and activation
-- codes: every incidental exposure of the column, a backup, a slow query log, a support
-- export, then yields hashes rather than live session handles.
--
-- owner is 'authserver' or 'adminconsole'. One table serves both applications because
-- the two row shapes are identical, and the column is what keeps the two populations
-- apart. owner and session_id_hash are NOT NULL because database/sql cannot scan NULL
-- into a Go string, the reasoning migration 000028 records.
--
-- The UNIQUE index on (owner, session_id_hash) is the lookup key: an identifier is only
-- ever resolved together with the application it belongs to. The plain index on
-- expires_at serves the background reaper, which deletes on that column alone.
CREATE TABLE browser_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    owner TEXT NOT NULL,
    session_id_hash TEXT NOT NULL,
    data longtext,
    last_accessed DATETIME NOT NULL,
    expires_at DATETIME NOT NULL
);
CREATE UNIQUE INDEX idx_browser_sessions_owner_hash ON browser_sessions(owner, session_id_hash);
CREATE INDEX idx_browser_sessions_expires_at ON browser_sessions(expires_at);

-- The admin console keeps no database connection of its own, so it reaches its rows in
-- the table above through an endpoint on the auth server, authenticated with a bearer
-- token it obtains through client_credentials. The permission below is what that token
-- carries, and it is deliberately NOT one of the manage-* admin API scopes: it permits
-- reading and writing admin console browser sessions and nothing else, so holding the
-- admin console's secret does not drive the whole admin API.
--
-- Guarded with NOT EXISTS, in the shape migration 000012 established, so re-running this
-- file inserts nothing. An installation seeded by a newer binary already carries both
-- rows.
INSERT INTO permissions (created_at, updated_at, permission_identifier, description, resource_id)
SELECT datetime('now'), datetime('now'), 'browser-sessions', 'Read and write admin console browser sessions', id
FROM resources WHERE resource_identifier = 'authserver'
AND NOT EXISTS (SELECT 1 FROM permissions WHERE permission_identifier = 'browser-sessions' AND resource_id = (SELECT id FROM resources WHERE resource_identifier = 'authserver'));

INSERT INTO clients_permissions (created_at, updated_at, client_id, permission_id)
SELECT datetime('now'), datetime('now'), c.id, p.id
FROM clients c CROSS JOIN permissions p
WHERE c.client_identifier = 'admin-console-client'
AND p.permission_identifier = 'browser-sessions'
AND p.resource_id = (SELECT id FROM resources WHERE resource_identifier = 'authserver')
AND NOT EXISTS (SELECT 1 FROM clients_permissions cp WHERE cp.client_id = c.id AND cp.permission_id = p.id);

-- The boolean literal differs by engine and a wrong one matches nothing SILENTLY rather
-- than failing: client_credentials_enabled is `numeric` here, `tinyint(1)` on MySQL and
-- `BIT` on SQL Server, all of which take 1, and `boolean` on PostgreSQL, which takes
-- true.
UPDATE clients SET client_credentials_enabled = 1 WHERE client_identifier = 'admin-console-client';
