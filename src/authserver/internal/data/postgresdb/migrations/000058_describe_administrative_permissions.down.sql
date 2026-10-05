-- Puts back the wording the seed and 000012 gave the four permissions, on the rows that still carry
-- the wording 000058 wrote. A description an operator edited after 000058 is theirs and is kept.

UPDATE public.permissions SET description = 'Manage the authorization server via the admin console', updated_at = NOW()
WHERE permission_identifier = 'manage' AND description = 'Full administration, including administrators and administrative permissions'
AND resource_id = (SELECT id FROM public.resources WHERE resource_identifier = 'authserver');

UPDATE public.permissions SET description = 'Manage users, groups, and permissions', updated_at = NOW()
WHERE permission_identifier = 'manage-users' AND description = 'Manage users and groups that are not administrators, and their non-administrative permissions'
AND resource_id = (SELECT id FROM public.resources WHERE resource_identifier = 'authserver');

UPDATE public.permissions SET description = 'Manage OAuth2 clients', updated_at = NOW()
WHERE permission_identifier = 'manage-clients' AND description = 'Manage OAuth2 clients that are not administrators'
AND resource_id = (SELECT id FROM public.resources WHERE resource_identifier = 'authserver');

UPDATE public.permissions SET description = 'Manage system settings and signing keys', updated_at = NOW()
WHERE permission_identifier = 'manage-settings' AND description = 'Manage system settings, except email and audit logging, and signing keys'
AND resource_id = (SELECT id FROM public.resources WHERE resource_identifier = 'authserver');
