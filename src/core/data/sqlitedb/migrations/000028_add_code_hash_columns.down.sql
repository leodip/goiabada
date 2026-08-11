-- Drops what the up migration added. NOT a true inverse: the up migration deletes every
-- pre_registrations row and nothing here can bring them back, so rolling back leaves the
-- table empty rather than as it was (#112). See the up migration for why that delete
-- cannot be avoided.
DROP INDEX idx_users_forgot_password_code_hash;
DROP INDEX idx_pre_reg_verification_code_hash;

ALTER TABLE users DROP COLUMN forgot_password_code_hash;
ALTER TABLE pre_registrations DROP COLUMN verification_code_hash;
