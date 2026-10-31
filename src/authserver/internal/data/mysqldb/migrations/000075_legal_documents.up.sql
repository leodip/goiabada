-- Legal documents (#622 decisions 1 to 5). See the sqlite migration of the same number for why and
-- for the six questions.
--
-- Both tables are pinned to the case- and accent-sensitive collation every table here carries
-- (#283). The Markdown columns are longtext, as audit_logs.details is, so no engine caps a document
-- below the API's bound. The unique index on a version's document and number leads with
-- legal_document_id, so InnoDB uses it for the foreign key and creates no index of its own.
CREATE TABLE `legal_documents` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT,
    `created_at` datetime(6) DEFAULT NULL,
    `updated_at` datetime(6) DEFAULT NULL,
    `short_name` varchar(64) NOT NULL,
    `kind` varchar(20) NOT NULL,
    `draft_title` varchar(200) DEFAULT NULL,
    `draft_markdown` longtext,
    `retired_at` datetime(6) DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_legal_documents_short_name` (`short_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
CREATE TABLE `legal_document_versions` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT,
    `published_at` datetime(6) NOT NULL,
    `legal_document_id` bigint unsigned NOT NULL,
    `version_number` int NOT NULL,
    `title` varchar(200) NOT NULL,
    `markdown` longtext NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_legal_document_versions_document_version` (`legal_document_id`, `version_number`),
    CONSTRAINT `fk_legal_document_versions_document` FOREIGN KEY (`legal_document_id`) REFERENCES `legal_documents` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
