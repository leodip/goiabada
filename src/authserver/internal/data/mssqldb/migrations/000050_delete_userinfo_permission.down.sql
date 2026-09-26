-- Restores the authserver resource's userinfo permission, with the description the seed gave it,
-- when the resource exists and the row does not. The grants 000050 deleted are not restored.
INSERT INTO [permissions] ([created_at], [updated_at], [permission_identifier], [description], [resource_id])
SELECT GETDATE(), GETDATE(), 'userinfo', 'Access to the OpenID Connect user info endpoint', [id]
FROM [resources] WHERE [resource_identifier] = 'authserver'
AND NOT EXISTS (SELECT 1 FROM [permissions] WHERE [permission_identifier] = 'userinfo' AND [resource_id] = (SELECT [id] FROM [resources] WHERE [resource_identifier] = 'authserver'));
