-- Reverses migration 000035 (#266). See the sqlite migration of the same number for why
-- this down is lossy in two directions, and why the indexes are not dropped
-- separately.
DELETE FROM public.clients_permissions
WHERE permission_id IN (
    SELECT p.id FROM public.permissions p
    JOIN public.resources r ON r.id = p.resource_id
    WHERE p.permission_identifier = 'browser-sessions' AND r.resource_identifier = 'authserver'
);

DELETE FROM public.permissions
WHERE permission_identifier = 'browser-sessions'
AND resource_id = (SELECT id FROM public.resources WHERE resource_identifier = 'authserver');

UPDATE public.clients SET client_credentials_enabled = false WHERE client_identifier = 'admin-console-client';

DROP TABLE browser_sessions;
