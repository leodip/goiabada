-- Back to the width the four columns carried before #632.
--
-- Each MODIFY narrows the column to 64 characters, so a stored value that grew past that is
-- refused under MySQL 8's default strict sql_mode, and the file fails with the value whole, rather
-- than cut to an address that is no longer the person's. Under a non-strict sql_mode MySQL would
-- truncate it instead. Not transactional, for the reason the up file gives: a refusal on a later
-- table leaves the earlier ones narrowed and the version dirty, and once the value fits, clearing
-- the dirty version and running the file again completes it.
ALTER TABLE `users`
    MODIFY `email` VARCHAR(64) COLLATE utf8mb4_0900_as_cs NULL;

ALTER TABLE `pre_registrations`
    MODIFY `email` VARCHAR(64) COLLATE utf8mb4_0900_as_cs NULL;

ALTER TABLE `settings`
    MODIFY `smtp_from_email` VARCHAR(64) COLLATE utf8mb4_0900_as_cs NULL,
    MODIFY `smtp_username` VARCHAR(64) COLLATE utf8mb4_0900_as_cs NULL;
