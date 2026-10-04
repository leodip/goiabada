-- The shared counts of the credential-guessing rate limits (#394). See the sqlite migration of the
-- same number for why, what a row is, and the six questions.
--
-- key_hash is varchar(64), a hex SHA-256, and the table is pinned to the case- and
-- accent-sensitive collation every table here carries (#283), so the primary key means what it
-- says.
CREATE TABLE `rate_limit_counters` (
    `key_hash` varchar(64) NOT NULL,
    `window_start` datetime(6) NOT NULL,
    `hits` int NOT NULL,
    `expires_at` datetime(6) NOT NULL,
    PRIMARY KEY (`key_hash`, `window_start`),
    KEY `idx_rate_limit_counters_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
