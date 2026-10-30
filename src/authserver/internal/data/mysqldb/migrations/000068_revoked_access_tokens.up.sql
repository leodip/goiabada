-- An access token without a grant is revoked by its jti (#676 decision 1). See the sqlite migration
-- of the same number for why, for the six questions and for what the index serves.
--
-- jti is varchar(64), the width of refresh_tokens.refresh_token_jti, and the table is pinned to the
-- case- and accent-sensitive collation every table here carries (#283), so the primary key means
-- what it says.
CREATE TABLE `revoked_access_tokens` (
    `jti` varchar(64) NOT NULL,
    `expires_at` datetime(6) NOT NULL,
    PRIMARY KEY (`jti`),
    KEY `idx_revoked_access_tokens_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
