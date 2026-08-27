-- Reverses migration 000035 (#266). See the up migration for what browser_sessions
-- holds and why it is not named http_sessions.
--
-- DROP TABLE takes both indexes with it on every engine, so they are not dropped
-- separately.
--
-- Resetting client_credentials_enabled to false is lossy by construction: an operator
-- could have enabled the client-credentials grant on admin-console-client themselves,
-- and nothing here can tell that apart from what the up migration set. This down exists
-- for the migration test and for a rollback of this change, not as a general undo.
--
-- The grant goes before the permission it references, and the permission before the
-- table, so no statement runs against a row another has already removed.
DELETE FROM clients_permissions
WHERE permission_id IN (
    SELECT p.id FROM permissions p
    JOIN resources r ON r.id = p.resource_id
    WHERE p.permission_identifier = 'browser-sessions' AND r.resource_identifier = 'authserver'
);

DELETE FROM permissions
WHERE permission_identifier = 'browser-sessions'
AND resource_id = (SELECT id FROM resources WHERE resource_identifier = 'authserver');

UPDATE clients SET client_credentials_enabled = 0 WHERE client_identifier = 'admin-console-client';

DROP TABLE browser_sessions;
