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

-- client_credentials_enabled is a genuine `boolean` here, unlike the other three
-- engines, so the literal is true. Writing 1 would be a type error rather than a silent
-- no-op, but the pair is spelled out because the reverse mistake, `= true` on an integer
-- column, matches nothing and reports success.
UPDATE public.clients SET client_credentials_enabled = true WHERE client_identifier = 'admin-console-client';
