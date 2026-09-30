-- parity: mysql, postgres and mssql only. SQLite stores all five columns as TEXT, which has no width.
--
-- Widens the five columns an authorization request's free-form values are stored in from 512 to
-- 2048 (#437): codes.state, codes.nonce, and the three scope columns, codes.scope,
-- refresh_tokens.scope and user_consents.scope. The authorization endpoint now refuses a state or
-- a nonce longer than 2048 bytes, and it and the password grant refuse a scope longer than that.
-- Nothing bounded any of the five before, so a value between 512 and its limit was accepted at the
-- authorization endpoint and refused by the column, as a 500, at the consent save or at /auth/issue
-- after the user had signed in.
--
-- The three scope columns move together because one scope is stored in all three: the consent the
-- user gave, the code issued under it and the refresh token descended from that code. A width that
-- fitted the first and not the last would grant a scope and then fail to issue it.
--
-- The handlers bound all three values in bytes, and MySQL counts a VARCHAR's width in characters,
-- so a value they admit is never wider than the column. MODIFY replaces the whole column
-- definition, so the collation and NOT NULL are restated; none of the five carries a default. A
-- VARCHAR of 512 characters already takes a two-byte length prefix under utf8mb4, as one of 2048
-- does, so the widening is a change to the table's metadata and rewrites no row. The declared
-- VARCHAR totals stay inside InnoDB's 65535-byte row limit: codes 37480 bytes, refresh_tokens
-- 9280, user_consents 8192.
--
-- MySQL DDL is not transactional: each statement commits on its own, so a failure part way leaves
-- the earlier tables widened and the version dirty. Each MODIFY is idempotent, so clearing the
-- dirty version and running the file again completes it.
ALTER TABLE `codes`
    MODIFY `state` VARCHAR(2048) COLLATE utf8mb4_0900_as_cs NOT NULL,
    MODIFY `nonce` VARCHAR(2048) COLLATE utf8mb4_0900_as_cs NOT NULL,
    MODIFY `scope` VARCHAR(2048) COLLATE utf8mb4_0900_as_cs NOT NULL;

ALTER TABLE `refresh_tokens`
    MODIFY `scope` VARCHAR(2048) COLLATE utf8mb4_0900_as_cs NOT NULL;

ALTER TABLE `user_consents`
    MODIFY `scope` VARCHAR(2048) COLLATE utf8mb4_0900_as_cs NOT NULL;
