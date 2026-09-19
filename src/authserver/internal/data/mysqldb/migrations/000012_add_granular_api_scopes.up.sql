-- Add granular API scopes for fine-grained authorization
-- These permissions allow delegating specific admin functions without full access

INSERT INTO `permissions` (`created_at`, `updated_at`, `permission_identifier`, `description`, `resource_id`)
SELECT NOW(), NOW(), 'admin-read', 'Read-only access to all admin API endpoints', `id`
FROM `resources` WHERE `resource_identifier` = 'authserver'
AND NOT EXISTS (SELECT 1 FROM `permissions` WHERE `permission_identifier` = 'admin-read' AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver'));

INSERT INTO `permissions` (`created_at`, `updated_at`, `permission_identifier`, `description`, `resource_id`)
SELECT NOW(), NOW(), 'manage-users', 'Manage users, groups, and permissions', `id`
FROM `resources` WHERE `resource_identifier` = 'authserver'
AND NOT EXISTS (SELECT 1 FROM `permissions` WHERE `permission_identifier` = 'manage-users' AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver'));

INSERT INTO `permissions` (`created_at`, `updated_at`, `permission_identifier`, `description`, `resource_id`)
SELECT NOW(), NOW(), 'manage-clients', 'Manage OAuth2 clients', `id`
FROM `resources` WHERE `resource_identifier` = 'authserver'
AND NOT EXISTS (SELECT 1 FROM `permissions` WHERE `permission_identifier` = 'manage-clients' AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver'));

INSERT INTO `permissions` (`created_at`, `updated_at`, `permission_identifier`, `description`, `resource_id`)
SELECT NOW(), NOW(), 'manage-settings', 'Manage system settings and signing keys', `id`
FROM `resources` WHERE `resource_identifier` = 'authserver'
AND NOT EXISTS (SELECT 1 FROM `permissions` WHERE `permission_identifier` = 'manage-settings' AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver'));
