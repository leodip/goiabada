-- Remove granular API scopes
DELETE FROM public.permissions
WHERE permission_identifier IN ('admin-read', 'manage-users', 'manage-clients', 'manage-settings')
AND resource_id = (SELECT id FROM public.resources WHERE resource_identifier = 'authserver');
