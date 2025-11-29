-- Remove granular API scopes
DELETE FROM `permissions`
WHERE `permission_identifier` IN ('admin-read', 'manage-users', 'manage-clients', 'manage-settings')
AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver');
