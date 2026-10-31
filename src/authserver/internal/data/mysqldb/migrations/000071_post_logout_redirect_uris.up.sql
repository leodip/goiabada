-- A client's sign-out redirect URIs (#147 decision 2). See the sqlite migration of the same number
-- for why and for the six questions.
--
-- The table mirrors redirect_uris: uri is varchar(2048), the width of redirect_uris.uri, the table is
-- pinned to the case- and accent-sensitive collation every table here carries (#283), and client_id
-- carries the foreign key's own index, as redirect_uris' does.
CREATE TABLE `post_logout_redirect_uris` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT,
    `created_at` datetime(6) DEFAULT NULL,
    `uri` varchar(2048) NOT NULL,
    `client_id` bigint unsigned NOT NULL,
    PRIMARY KEY (`id`),
    KEY `fk_clients_post_logout_redirect_uris` (`client_id`),
    CONSTRAINT `fk_clients_post_logout_redirect_uris` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
