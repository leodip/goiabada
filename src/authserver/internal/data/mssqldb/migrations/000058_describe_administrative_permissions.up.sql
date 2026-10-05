-- Rewrites the descriptions of four administrative permissions on the authserver resource where
-- the seeded wording remains (#402 decision 3). See the sqlite migration of the same number for
-- why, and why an edited description is kept. description is pinned to a case- and
-- accent-sensitive collation, so the comparison is exact but for trailing spaces, which SQL Server
-- ignores when it compares strings.
--
-- ATOMIC, as 000050 is: the runner hands a SQL Server file to one Exec and opens no transaction,
-- so without the pair below each UPDATE autocommits on its own. The statements are re-runnable in
-- order in any case.
SET XACT_ABORT ON;
BEGIN TRANSACTION;

UPDATE [permissions] SET [description] = 'Full administration, including administrators and administrative permissions', [updated_at] = GETDATE()
WHERE [permission_identifier] = 'manage' AND [description] = 'Manage the authorization server via the admin console'
AND [resource_id] = (SELECT [id] FROM [resources] WHERE [resource_identifier] = 'authserver');

UPDATE [permissions] SET [description] = 'Manage users and groups that are not administrators, and their non-administrative permissions', [updated_at] = GETDATE()
WHERE [permission_identifier] = 'manage-users' AND [description] = 'Manage users, groups, and permissions'
AND [resource_id] = (SELECT [id] FROM [resources] WHERE [resource_identifier] = 'authserver');

UPDATE [permissions] SET [description] = 'Manage OAuth2 clients that are not administrators', [updated_at] = GETDATE()
WHERE [permission_identifier] = 'manage-clients' AND [description] = 'Manage OAuth2 clients'
AND [resource_id] = (SELECT [id] FROM [resources] WHERE [resource_identifier] = 'authserver');

UPDATE [permissions] SET [description] = 'Manage system settings, except email and audit logging, and signing keys', [updated_at] = GETDATE()
WHERE [permission_identifier] = 'manage-settings' AND [description] = 'Manage system settings and signing keys'
AND [resource_id] = (SELECT [id] FROM [resources] WHERE [resource_identifier] = 'authserver');

COMMIT TRANSACTION;
