-- Per-user one-time-use marker for TOTP codes (#111). See the sqlite migration of
-- the same number for what the column means and why existing rows land at 0.
ALTER TABLE users ADD COLUMN last_otp_step bigint NOT NULL DEFAULT 0;
