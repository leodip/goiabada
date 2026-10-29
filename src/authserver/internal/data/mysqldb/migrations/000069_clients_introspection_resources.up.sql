-- A client's introspection resources (#676 decisions 5 and 14). See the sqlite migration of the
-- same number for why, for the six questions and for what each index serves.
--
-- The id columns are bigint unsigned, as the ids they name are. The table holds no string column,
-- and is pinned to the case- and accent-sensitive collation every table here carries (#283), so a
-- column added to it later starts there.
CREATE TABLE `clients_introspection_resources` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT,
    `created_at` datetime(6) DEFAULT NULL,
    `client_id` bigint unsigned NOT NULL,
    `resource_id` bigint unsigned NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_clients_introspection_resources_client_resource` (`client_id`, `resource_id`),
    KEY `idx_clients_introspection_resources_resource_id` (`resource_id`),
    CONSTRAINT `fk_clients_introspection_resources_client` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_clients_introspection_resources_resource` FOREIGN KEY (`resource_id`) REFERENCES `resources` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
