-- Per-user count of consecutive failed attempts against the enrolled authenticator
-- (#489). See the sqlite migration of the same number for what the column means and
-- why existing rows land at 0.
ALTER TABLE users ADD COLUMN otp_consecutive_failures bigint NOT NULL DEFAULT 0;