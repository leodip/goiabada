-- Email template edits (#818 decision 7). See the sqlite migration of the same number for why and
-- for the six questions.
--
-- The table is pinned to the case- and accent-sensitive collation every table here carries (#283).
-- The body is longtext, as the legal documents' Markdown is, so no engine caps it below the API's
-- bound. The unique index leads with the email, so the email's edits in every language are one
-- range of it.
CREATE TABLE `email_templates` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT,
    `created_at` datetime(6) DEFAULT NULL,
    `updated_at` datetime(6) DEFAULT NULL,
    `email_template` varchar(64) NOT NULL,
    `language` varchar(32) NOT NULL,
    `subject` varchar(200) DEFAULT NULL,
    `button_label` varchar(60) DEFAULT NULL,
    `body` longtext,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_email_templates_email_template_language` (`email_template`, `language`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
