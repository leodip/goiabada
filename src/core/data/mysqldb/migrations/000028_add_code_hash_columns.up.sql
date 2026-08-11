-- Look up a reset or activation link by an unsalted SHA-256 of its code (#112). See the
-- sqlite migration of the same number for what the columns mean, why one index is plain
-- and the other UNIQUE, and why the DELETE below makes this migration irreversible.
DELETE FROM `pre_registrations`;

ALTER TABLE `users` ADD COLUMN `forgot_password_code_hash` varchar(64) NOT NULL DEFAULT '';
ALTER TABLE `pre_registrations` ADD COLUMN `verification_code_hash` varchar(64) NOT NULL DEFAULT '';

CREATE INDEX `idx_users_forgot_password_code_hash`
    ON `users`(`forgot_password_code_hash`);
CREATE UNIQUE INDEX `idx_pre_reg_verification_code_hash`
    ON `pre_registrations`(`verification_code_hash`);
