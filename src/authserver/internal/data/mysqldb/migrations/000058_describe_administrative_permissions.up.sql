-- Rewrites the descriptions of four administrative permissions on the authserver resource where
-- the seeded wording remains (#402 decision 3). See the sqlite migration of the same number for
-- why, and why an edited description is kept. description is pinned to utf8mb4_0900_as_cs, so the
-- comparison is exact. The runner opens no transaction on this engine; each statement is
-- re-runnable, so a failure part way is completed by clearing the dirty version and running the
-- file again.

UPDATE `permissions` SET `description` = 'Full administration, including administrators and administrative permissions', `updated_at` = NOW()
WHERE `permission_identifier` = 'manage' AND `description` = 'Manage the authorization server via the admin console'
AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver');

UPDATE `permissions` SET `description` = 'Manage users and groups that are not administrators, and their non-administrative permissions', `updated_at` = NOW()
WHERE `permission_identifier` = 'manage-users' AND `description` = 'Manage users, groups, and permissions'
AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver');

UPDATE `permissions` SET `description` = 'Manage OAuth2 clients that are not administrators', `updated_at` = NOW()
WHERE `permission_identifier` = 'manage-clients' AND `description` = 'Manage OAuth2 clients'
AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver');

UPDATE `permissions` SET `description` = 'Manage system settings, except email and audit logging, and signing keys', `updated_at` = NOW()
WHERE `permission_identifier` = 'manage-settings' AND `description` = 'Manage system settings and signing keys'
AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver');
