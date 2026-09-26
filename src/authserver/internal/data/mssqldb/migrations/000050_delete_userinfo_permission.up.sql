-- Deletes the authserver resource's userinfo permission and every user, group and client grant of
-- it (#449). See the sqlite migration of the same number for why no user loses anything by it.
--
-- The grants are deleted explicitly, before the permission, as on every engine, so the four agree
-- without relying on the link tables' ON DELETE CASCADE.
--
-- ATOMIC, as 000049 is: the runner hands a SQL Server file to one Exec and opens no transaction,
-- so without the pair below each DELETE autocommits on its own. The statements are re-runnable in
-- order in any case.
SET XACT_ABORT ON;
BEGIN TRANSACTION;

DELETE FROM [users_permissions]
WHERE [permission_id] IN (SELECT [p].[id] FROM [permissions] [p] JOIN [resources] [r] ON [r].[id] = [p].[resource_id]
                          WHERE [r].[resource_identifier] = 'authserver' AND [p].[permission_identifier] = 'userinfo');

DELETE FROM [groups_permissions]
WHERE [permission_id] IN (SELECT [p].[id] FROM [permissions] [p] JOIN [resources] [r] ON [r].[id] = [p].[resource_id]
                          WHERE [r].[resource_identifier] = 'authserver' AND [p].[permission_identifier] = 'userinfo');

DELETE FROM [clients_permissions]
WHERE [permission_id] IN (SELECT [p].[id] FROM [permissions] [p] JOIN [resources] [r] ON [r].[id] = [p].[resource_id]
                          WHERE [r].[resource_identifier] = 'authserver' AND [p].[permission_identifier] = 'userinfo');

DELETE FROM [permissions]
WHERE [permission_identifier] = 'userinfo'
AND [resource_id] = (SELECT [id] FROM [resources] WHERE [resource_identifier] = 'authserver');

COMMIT TRANSACTION;
