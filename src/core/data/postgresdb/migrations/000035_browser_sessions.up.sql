-- The browser session moves out of the cookie and into a row (#266). See the sqlite
-- migration of the same number for why the table is named browser_sessions rather than
-- http_sessions, why session_id_hash holds a digest rather than the identifier, what the
-- owner column keeps apart, and why the new permission is narrow.
CREATE TABLE browser_sessions (
    id BIGSERIAL PRIMARY KEY,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    owner character varying(20) NOT NULL,
    session_id_hash character varying(64) NOT NULL,
    data TEXT,
    last_accessed timestamp(6) without time zone NOT NULL,
    expires_at timestamp(6) without time zone NOT NULL
);
CREATE UNIQUE INDEX idx_browser_sessions_owner_hash ON browser_sessions(owner, session_id_hash);
CREATE INDEX idx_browser_sessions_expires_at ON browser_sessions(expires_at);

INSERT INTO public.permissions (created_at, updated_at, permission_identifier, description, resource_id)
SELECT NOW(), NOW(), 'browser-sessions', 'Read and write admin console browser sessions', id
FROM public.resources WHERE resource_identifier = 'authserver'
AND NOT EXISTS (SELECT 1 FROM public.permissions WHERE permission_identifier = 'browser-sessions' AND resource_id = (SELECT id FROM public.resources WHERE resource_identifier = 'authserver'));

INSERT INTO public.clients_permissions (created_at, updated_at, client_id, permission_id)
SELECT NOW(), NOW(), c.id, p.id
FROM public.clients c CROSS JOIN public.permissions p
WHERE c.client_identifier = 'admin-console-client'
AND p.permission_identifier = 'browser-sessions'
AND p.resource_id = (SELECT id FROM public.resources WHERE resource_identifier = 'authserver')
AND NOT EXISTS (SELECT 1 FROM public.clients_permissions cp WHERE cp.client_id = c.id AND cp.permission_id = p.id);

-- Every grant admin-console-client holds other than the browser-sessions one above is
-- deleted, so an upgrade cannot reactivate a permission the client was left carrying
-- (#266, decision 21). See the sqlite migration of the same number for why it runs
-- before the UPDATE and why it excludes one row rather than deleting them all.
DELETE FROM public.clients_permissions
WHERE client_id = (SELECT id FROM public.clients WHERE client_identifier = 'admin-console-client')
AND permission_id <> (
    SELECT p.id FROM public.permissions p
    JOIN public.resources r ON r.id = p.resource_id
    WHERE p.permission_identifier = 'browser-sessions' AND r.resource_identifier = 'authserver'
);

-- Every grant of the browser-sessions permission held by any principal other than
-- admin-console-client is deleted too, across all three principal tables (#266, decision
-- 22). See the sqlite migration of the same number for why the guarded INSERT above can
-- adopt a permission of that name an administrator already made, why a user or group grant
-- is not a lesser case than a client one, and why the client statement says NOT EXISTS
-- rather than excluding the client with a scalar subquery.
--
-- The correlated reference is spelled clients_permissions.client_id without the schema:
-- the DELETE's target enters the query's range table under the bare relation name, which
-- is what an inner query correlates to.
DELETE FROM public.clients_permissions
WHERE permission_id = (
    SELECT p.id FROM public.permissions p
    JOIN public.resources r ON r.id = p.resource_id
    WHERE p.permission_identifier = 'browser-sessions' AND r.resource_identifier = 'authserver'
)
AND NOT EXISTS (
    SELECT 1 FROM public.clients c
    WHERE c.id = clients_permissions.client_id AND c.client_identifier = 'admin-console-client'
);

DELETE FROM public.users_permissions
WHERE permission_id = (
    SELECT p.id FROM public.permissions p
    JOIN public.resources r ON r.id = p.resource_id
    WHERE p.permission_identifier = 'browser-sessions' AND r.resource_identifier = 'authserver'
);

DELETE FROM public.groups_permissions
WHERE permission_id = (
    SELECT p.id FROM public.permissions p
    JOIN public.resources r ON r.id = p.resource_id
    WHERE p.permission_identifier = 'browser-sessions' AND r.resource_identifier = 'authserver'
);

-- client_credentials_enabled is a genuine `boolean` here, unlike the other three
-- engines, so the literal is true. Writing 1 would be a type error rather than a silent
-- no-op, but the pair is spelled out because the reverse mistake, `= true` on an integer
-- column, matches nothing and reports success.
UPDATE public.clients SET client_credentials_enabled = true WHERE client_identifier = 'admin-console-client';
