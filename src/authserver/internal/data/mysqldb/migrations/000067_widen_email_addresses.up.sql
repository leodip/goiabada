-- parity: mysql, postgres and mssql only. SQLite stores all four columns as TEXT, which has no width.
--
-- Widens the four columns an email address is stored in from 64 to 254 characters (#632):
-- users.email and pre_registrations.email, where an account's address is kept, and
-- settings.smtp_from_email and settings.smtp_username, the sender address and the SMTP username,
-- which for the common hosted mail providers is the mailbox's own address. 254 is the longest
-- address SMTP can carry: RFC 5321 section 4.5.3.1.3 bounds a path at 256 octets including its
-- angle brackets.
--
-- The address rule admits ASCII only, so its characters are its bytes. MODIFY replaces the whole
-- column definition, so the collation and NULL are restated; none of the four carries a default.
-- A VARCHAR of 64 characters already takes a two-byte length prefix under utf8mb4, as one of 254
-- does, so the widening is a change to the table's metadata. The unique index idx_email covers
-- users.email, and its widened key of 1016 bytes stays inside InnoDB's 3072; idx_pre_reg_email
-- covers pre_registrations.email at the same width. The declared VARCHAR totals stay far inside
-- InnoDB's 65535-byte row limit: users 6200 bytes, pre_registrations 1272, settings 3376.
--
-- MySQL DDL is not transactional: each statement commits on its own, so a failure part way leaves
-- the earlier tables widened and the version dirty. Each MODIFY is idempotent, so clearing the
-- dirty version and running the file again completes it.
ALTER TABLE `users`
    MODIFY `email` VARCHAR(254) COLLATE utf8mb4_0900_as_cs NULL;

ALTER TABLE `pre_registrations`
    MODIFY `email` VARCHAR(254) COLLATE utf8mb4_0900_as_cs NULL;

ALTER TABLE `settings`
    MODIFY `smtp_from_email` VARCHAR(254) COLLATE utf8mb4_0900_as_cs NULL,
    MODIFY `smtp_username` VARCHAR(254) COLLATE utf8mb4_0900_as_cs NULL;
