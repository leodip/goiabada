-- The browser session moves out of the cookie and into a row (#266). See the sqlite
-- migration of the same number for why the table is named browser_sessions rather than
-- http_sessions, why session_id_hash holds a digest rather than the identifier, what the
-- owner column keeps apart, and why the new permission is narrow.
CREATE TABLE `browser_sessions` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `created_at` datetime(6) DEFAULT NULL,
    `updated_at` datetime(6) DEFAULT NULL,
    `owner` varchar(20) NOT NULL,
    `session_id_hash` varchar(64) NOT NULL,
    `data` longtext,
    `last_accessed` datetime(6) NOT NULL,
    `expires_at` datetime(6) NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_browser_sessions_owner_hash` (`owner`, `session_id_hash`),
    KEY `idx_browser_sessions_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO `permissions` (`created_at`, `updated_at`, `permission_identifier`, `description`, `resource_id`)
SELECT NOW(), NOW(), 'browser-sessions', 'Read and write admin console browser sessions', `id`
FROM `resources` WHERE `resource_identifier` = 'authserver'
AND NOT EXISTS (SELECT 1 FROM `permissions` WHERE `permission_identifier` = 'browser-sessions' AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver'));

INSERT INTO `clients_permissions` (`created_at`, `updated_at`, `client_id`, `permission_id`)
SELECT NOW(), NOW(), c.`id`, p.`id`
FROM `clients` c CROSS JOIN `permissions` p
WHERE c.`client_identifier` = 'admin-console-client'
AND p.`permission_identifier` = 'browser-sessions'
AND p.`resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver')
AND NOT EXISTS (SELECT 1 FROM `clients_permissions` cp WHERE cp.`client_id` = c.`id` AND cp.`permission_id` = p.`id`);

-- client_credentials_enabled is tinyint(1) here, so the literal is 1.
UPDATE `clients` SET `client_credentials_enabled` = 1 WHERE `client_identifier` = 'admin-console-client';
