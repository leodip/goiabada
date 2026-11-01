-- Which user accepted which published version of a must-accept legal document, and when (#622).
-- See the sqlite migration of the same number for why, for the six questions and for what each
-- index serves.
--
-- The id columns are bigint unsigned, as the ids they name are. The table holds no string column,
-- and is pinned to the case- and accent-sensitive collation every table here carries (#283), so a
-- column added to it later starts there.
CREATE TABLE `legal_document_acceptances` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT,
    `accepted_at` datetime(6) NOT NULL,
    `user_id` bigint unsigned NOT NULL,
    `legal_document_version_id` bigint unsigned NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_legal_document_acceptances_user_version` (`user_id`, `legal_document_version_id`),
    KEY `idx_legal_document_acceptances_version_id` (`legal_document_version_id`),
    CONSTRAINT `fk_legal_document_acceptances_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_legal_document_acceptances_version` FOREIGN KEY (`legal_document_version_id`) REFERENCES `legal_document_versions` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
