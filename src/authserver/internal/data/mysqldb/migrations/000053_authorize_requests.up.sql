-- A POST to /auth/authorize is parked in a row and answered with a 303 to a GET (#246, #437). See
-- the sqlite migration of the same number for why, why handle_hash holds a digest rather than the
-- handle, and what each index serves.
--
-- request_form is LONGTEXT, not TEXT: the merged query and body can exceed TEXT's 65,535 bytes
-- while every parameter respects the bounds /auth/authorize applies, and LONGTEXT is what
-- browser_sessions.data already uses for the same reason. The table is pinned to the case- and
-- accent-sensitive collation every table here carries (#283), so the unique index over
-- handle_hash means what it says.
CREATE TABLE `authorize_requests` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `created_at` datetime(6) DEFAULT NULL,
    `updated_at` datetime(6) DEFAULT NULL,
    `handle_hash` varchar(64) NOT NULL,
    `request_form` longtext NOT NULL,
    `expires_at` datetime(6) NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_authorize_requests_handle_hash` (`handle_hash`),
    KEY `idx_authorize_requests_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
