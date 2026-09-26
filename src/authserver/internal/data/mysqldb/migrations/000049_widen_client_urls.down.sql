-- Back to the width the three columns carried before #428.
--
-- Each MODIFY narrows the column to 256 characters, so a row that grew past that is refused under
-- MySQL 8's default strict sql_mode and truncated under a non-strict one. That is what restoring
-- the previous shape means here.
ALTER TABLE `redirect_uris`
    MODIFY `uri` VARCHAR(256) COLLATE utf8mb4_0900_as_cs NOT NULL;

ALTER TABLE `codes`
    MODIFY `redirect_uri` VARCHAR(256) COLLATE utf8mb4_0900_as_cs NOT NULL;

ALTER TABLE `web_origins`
    MODIFY `origin` VARCHAR(256) COLLATE utf8mb4_0900_as_cs NOT NULL;
