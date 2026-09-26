-- Deletes the authserver resource's userinfo permission and every user, group and client grant of
-- it (#449). Nothing on the sign-in path read the row: issuance appended authserver:userinfo to
-- every token carrying a claim scope whether or not the user held it, and /userinfo now gates on
-- the openid scope instead, so a grant of it granted nothing. No user loses the ability to sign in.
--
-- The grants are deleted explicitly, before the permission, rather than left to the ON DELETE
-- CASCADE the three link tables carry, so the result does not depend on this engine's
-- foreign_keys pragma being on for the migration's connection. The statements are re-runnable in
-- order, so a failure part way is completed by clearing the dirty version and running the file
-- again; this engine's runner wraps the file in one transaction regardless.
DELETE FROM users_permissions
WHERE permission_id IN (SELECT p.id FROM permissions p JOIN resources r ON r.id = p.resource_id
                        WHERE r.resource_identifier = 'authserver' AND p.permission_identifier = 'userinfo');

DELETE FROM groups_permissions
WHERE permission_id IN (SELECT p.id FROM permissions p JOIN resources r ON r.id = p.resource_id
                        WHERE r.resource_identifier = 'authserver' AND p.permission_identifier = 'userinfo');

DELETE FROM clients_permissions
WHERE permission_id IN (SELECT p.id FROM permissions p JOIN resources r ON r.id = p.resource_id
                        WHERE r.resource_identifier = 'authserver' AND p.permission_identifier = 'userinfo');

DELETE FROM permissions
WHERE permission_identifier = 'userinfo'
AND resource_id = (SELECT id FROM resources WHERE resource_identifier = 'authserver');
