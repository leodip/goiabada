-- parity: mysql, postgres and mssql only. SQLite stores all three columns as TEXT, which has no width.
--
-- Widens the three columns a client's URLs are stored in to the bounds the handlers now enforce
-- (#428). redirect_uris.uri goes to 2048, the bound dynamic client registration and the admin API
-- apply to a redirect URI, and codes.redirect_uri with it, because issuance copies the registered
-- URI there verbatim and RFC 6749 section 4.1.3 requires the token request's redirect_uri to be
-- identical to it: a callback that fitted the first and not the second would register and then
-- fail to issue a code. web_origins.origin goes to 267, the longest canonical origin ("https://"
-- plus a 253-character host plus ":65535"); the unique index idx_web_origins_origin_client covers
-- it, and its widened key of 1076 bytes stays inside InnoDB's 3072.
--
-- The handlers bound all three in bytes, and MySQL counts a VARCHAR's width in characters, so a
-- value they admit is never wider than the column. MODIFY replaces the whole column definition,
-- so the collation and NOT NULL are restated; none of the three carries a default.
--
-- MySQL DDL is not transactional: each statement commits on its own, so a failure part way leaves
-- the earlier columns widened and the version dirty. Each MODIFY is idempotent, so clearing the
-- dirty version and running the file again completes it.
ALTER TABLE `redirect_uris`
    MODIFY `uri` VARCHAR(2048) COLLATE utf8mb4_0900_as_cs NOT NULL;

ALTER TABLE `codes`
    MODIFY `redirect_uri` VARCHAR(2048) COLLATE utf8mb4_0900_as_cs NOT NULL;

ALTER TABLE `web_origins`
    MODIFY `origin` VARCHAR(267) COLLATE utf8mb4_0900_as_cs NOT NULL;
