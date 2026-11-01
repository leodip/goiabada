-- Which apps a legal document applies to (#622, "Applies to"). See the sqlite migration of the
-- same number for why, for the six questions and for what each index serves.
--
-- The id columns are bigint unsigned, as the ids they name are. The table holds no string column,
-- and is pinned to the case- and accent-sensitive collation every table here carries (#283), so a
-- column added to it later starts there.
ALTER TABLE `legal_documents` ADD COLUMN `applies_to_all_apps` tinyint(1) NOT NULL DEFAULT 1;
CREATE TABLE `legal_documents_clients` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT,
    `created_at` datetime(6) DEFAULT NULL,
    `legal_document_id` bigint unsigned NOT NULL,
    `client_id` bigint unsigned NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_legal_documents_clients_document_client` (`legal_document_id`, `client_id`),
    KEY `idx_legal_documents_clients_client_id` (`client_id`),
    CONSTRAINT `fk_legal_documents_clients_document` FOREIGN KEY (`legal_document_id`) REFERENCES `legal_documents` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_legal_documents_clients_client` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
