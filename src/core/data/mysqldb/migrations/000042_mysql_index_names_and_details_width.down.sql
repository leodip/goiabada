-- Back to the names and the width MySQL carried before #284's comparison ran.
--
-- The MODIFY narrows a 4 GiB column to 64 KiB, so a row whose details grew past that is
-- refused under MySQL 8's default strict sql_mode and truncated under a non-strict one.
-- That is what restoring the previous shape means here, and it is the reason the up
-- migration exists.
ALTER TABLE `audit_logs`
    MODIFY `details` TEXT COLLATE utf8mb4_0900_as_cs NOT NULL DEFAULT ('{}');

ALTER TABLE `user_sessions` RENAME INDEX `idx_user_sessions_user_id` TO `fk_user_sessions_user`;
ALTER TABLE `refresh_tokens` RENAME INDEX `idx_refresh_tokens_code_id` TO `fk_refresh_tokens_code`;
ALTER TABLE `codes` RENAME INDEX `idx_codes_user_id` TO `fk_codes_user`;
