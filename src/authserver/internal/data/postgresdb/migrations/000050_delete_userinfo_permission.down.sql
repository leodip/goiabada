-- Restores the authserver resource's userinfo permission, with the description the seed gave it,
-- when the resource exists and the row does not. The grants 000050 deleted are not restored.
INSERT INTO public.permissions (created_at, updated_at, permission_identifier, description, resource_id)
SELECT NOW(), NOW(), 'userinfo', 'Access to the OpenID Connect user info endpoint', id
FROM public.resources WHERE resource_identifier = 'authserver'
AND NOT EXISTS (SELECT 1 FROM public.permissions WHERE permission_identifier = 'userinfo' AND resource_id = (SELECT id FROM public.resources WHERE resource_identifier = 'authserver'));
