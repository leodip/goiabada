-- A user's recovery codes (#257 decisions 2 and 3). See the sqlite migration of the same number for
-- why, for the six questions and for what the index serves.
--
-- code_hash is varchar(64), the width of codes.code_hash, and the table is pinned to the case- and
-- accent-sensitive collation every table here carries (#283), so the key means what it says.
CREATE TABLE `user_recovery_codes` (
    `id` bigint unsigned NOT NULL AUTO_INCREMENT,
    `user_id` bigint unsigned NOT NULL,
    `code_hash` varchar(64) NOT NULL,
    `created_at` datetime(6) NOT NULL,
    `used_at` datetime(6) DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_user_recovery_codes_user_code_hash` (`user_id`, `code_hash`),
    CONSTRAINT `fk_user_recovery_codes_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
