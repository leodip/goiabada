-- Reverses migration 000035 (#266). See the sqlite migration of the same number for why
-- resetting client_credentials_enabled is lossy, and why the indexes are not dropped
-- separately.
DELETE cp FROM `clients_permissions` cp
JOIN `permissions` p ON p.`id` = cp.`permission_id`
JOIN `resources` r ON r.`id` = p.`resource_id`
WHERE p.`permission_identifier` = 'browser-sessions' AND r.`resource_identifier` = 'authserver';

DELETE FROM `permissions`
WHERE `permission_identifier` = 'browser-sessions'
AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver');

UPDATE `clients` SET `client_credentials_enabled` = 0 WHERE `client_identifier` = 'admin-console-client';

DROP TABLE `browser_sessions`;
