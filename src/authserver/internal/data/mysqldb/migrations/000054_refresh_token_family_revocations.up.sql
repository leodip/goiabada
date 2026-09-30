-- A revoked refresh token family is recorded, and a child born into one is refused (#132, #259,
-- #437). See the sqlite migration of the same number for why, and for the six questions.
--
-- first_refresh_token_jti is varchar(64), the width of refresh_tokens.first_refresh_token_jti, and
-- the table is pinned to the case- and accent-sensitive collation every table here carries (#283),
-- so the primary key means what it says and the join the worker's sweep makes compares two columns
-- under one collation.
CREATE TABLE `refresh_token_family_revocations` (
    `first_refresh_token_jti` varchar(64) NOT NULL,
    `reason` varchar(64) NOT NULL,
    `revoked_at` datetime(6) NOT NULL,
    PRIMARY KEY (`first_refresh_token_jti`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
