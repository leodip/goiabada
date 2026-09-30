-- Back to the width the five columns carried before #437.
--
-- Each MODIFY narrows the column to 512 characters, so a row that grew past that is refused under
-- MySQL 8's default strict sql_mode and truncated under a non-strict one. That is what restoring
-- the previous shape means here.
ALTER TABLE `codes`
    MODIFY `state` VARCHAR(512) COLLATE utf8mb4_0900_as_cs NOT NULL,
    MODIFY `nonce` VARCHAR(512) COLLATE utf8mb4_0900_as_cs NOT NULL,
    MODIFY `scope` VARCHAR(512) COLLATE utf8mb4_0900_as_cs NOT NULL;

ALTER TABLE `refresh_tokens`
    MODIFY `scope` VARCHAR(512) COLLATE utf8mb4_0900_as_cs NOT NULL;

ALTER TABLE `user_consents`
    MODIFY `scope` VARCHAR(512) COLLATE utf8mb4_0900_as_cs NOT NULL;
