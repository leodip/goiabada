-- Per-user OTP configuration generation (#242). See the sqlite migration of the same number for what
-- the columns mean, why both clauses of the seed are load-bearing, and why -1 is the seeded value.
--
-- The boolean literal is true here rather than 1: postgres declares both otp_enabled and
-- level2_auth_config_has_changed boolean, where the other three use numeric, tinyint(1) and BIT and
-- take 1. Each spelling is a type error on the other side, so this is not a literal the four files
-- can share.
ALTER TABLE users ADD COLUMN otp_config_generation bigint NOT NULL DEFAULT 0;
ALTER TABLE user_sessions ADD COLUMN otp_config_generation bigint NOT NULL DEFAULT 0;

UPDATE user_sessions SET otp_config_generation = -1
 WHERE level2_auth_config_has_changed = true
    OR user_id IN (SELECT id FROM users WHERE otp_enabled = true);

ALTER TABLE user_sessions DROP COLUMN level2_auth_config_has_changed;
