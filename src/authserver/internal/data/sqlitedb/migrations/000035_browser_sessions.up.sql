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

-- An upgrade must not reactivate a permission this client was already carrying (#266,
-- decision 21). The UPDATE below turns the client-credentials grant back on and nothing
-- above removes anything, so an installation where an administrator had once enabled
-- that grant, given the client a wide permission such as the authserver resource's
-- manage, and switched the grant off again would find that permission usable again from
-- here: a client_credentials token requested without a scope carries every permission
-- the client holds. Nor can the row be removed through the admin console, because the
-- permissions editor refuses to save while client credentials is off.
--
-- So every grant this client holds other than the browser-sessions one created above is
-- deleted. That is destructive and cannot be undone: an operator deliberately driving
-- the admin API with the admin console's own secret loses that and must create a client
-- of their own. The release notes say so in advance.
--
-- Two things about the shape. It runs BEFORE the UPDATE because MySQL and SQL Server do
-- not run a migration file in one transaction, so on those engines the statements commit
-- as they go and the wide grant has to be gone before the grant that makes it reachable
-- is switched on. And it excludes one permission rather than deleting them all and
-- re-inserting, because the subquery naming that permission yields NULL if it is somehow
-- absent, and `<> NULL` is unknown, so the statement then deletes nothing rather than
-- everything.
DELETE FROM clients_permissions
WHERE client_id = (SELECT id FROM clients WHERE client_identifier = 'admin-console-client')
AND permission_id <> (
    SELECT p.id FROM permissions p
    JOIN resources r ON r.id = p.resource_id
    WHERE p.permission_identifier = 'browser-sessions' AND r.resource_identifier = 'authserver'
);

-- The permission this file creates can be one an administrator already made (#266,
-- decision 22). The INSERT above is guarded with NOT EXISTS so that re-running the
-- migration inserts nothing, which means that on an installation where somebody had
-- already added a permission named exactly 'browser-sessions' to the authserver resource
-- it ADOPTS theirs rather than creating one. The session endpoint admits any token whose
-- scope carries authserver:browser-sessions and checks nothing about who presents it, so
-- from this release whatever that permission meant to them also means "may create and
-- delete admin console browser sessions".
--
-- Every grant of it held by anyone other than admin-console-client is therefore removed,
-- across all three principal tables. A user or a group grant is not a lesser case than a
-- client one: the authorize endpoint filters a requested scope against what the principal
-- holds, so such a grant carries into an ordinary access token and leaving those two would
-- leave the widest version of this open.
--
-- Destructive in the same way as the strip above and recorded the same way: a grant an
-- administrator meant is gone with no record of it, and the down migration cannot put it
-- back. The release notes carry the line.
--
-- The client statement is the mirror of the one above, keyed on the PERMISSION and
-- excluding the client where that one is keyed on the client and excludes the permission.
-- It says NOT EXISTS rather than `<> (SELECT id FROM clients ...)` deliberately, because
-- the two fail in opposite directions and only one of them is right here: with the scalar
-- form, an absent admin-console-client yields NULL, `<> NULL` is unknown and nothing is
-- deleted. But an installation with no admin console client has no legitimate holder of
-- this permission at all, so every grant should go. NOT EXISTS is the form that does that.
DELETE FROM clients_permissions
WHERE permission_id = (
    SELECT p.id FROM permissions p
    JOIN resources r ON r.id = p.resource_id
    WHERE p.permission_identifier = 'browser-sessions' AND r.resource_identifier = 'authserver'
)
AND NOT EXISTS (
    SELECT 1 FROM clients c
    WHERE c.id = clients_permissions.client_id AND c.client_identifier = 'admin-console-client'
);

-- No user and no group may hold this permission, so these two exclude nobody. The scalar
-- subquery yields NULL where the permission does not exist, and `= NULL` is unknown, so
-- they delete nothing rather than everything.
DELETE FROM users_permissions
WHERE permission_id = (
    SELECT p.id FROM permissions p
    JOIN resources r ON r.id = p.resource_id
    WHERE p.permission_identifier = 'browser-sessions' AND r.resource_identifier = 'authserver'
);

DELETE FROM groups_permissions
WHERE permission_id = (
    SELECT p.id FROM permissions p
    JOIN resources r ON r.id = p.resource_id
    WHERE p.permission_identifier = 'browser-sessions' AND r.resource_identifier = 'authserver'
);

-- The boolean literal differs by engine and a wrong one matches nothing SILENTLY rather
-- than failing: client_credentials_enabled is `numeric` here, `tinyint(1)` on MySQL and
-- `BIT` on SQL Server, all of which take 1, and `boolean` on PostgreSQL, which takes
-- true.
UPDATE clients SET client_credentials_enabled = 1 WHERE client_identifier = 'admin-console-client';
