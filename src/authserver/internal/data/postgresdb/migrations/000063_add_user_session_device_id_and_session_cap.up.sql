-- A session's device identifier and the per-user session cap (#564 decision 11). See the sqlite
-- migration of the same number for what the two columns hold, and why each carries a default rather
-- than a backfill.
--
-- 64 characters is a SHA-256 in hex.
ALTER TABLE user_sessions ADD COLUMN device_id varchar(64) NOT NULL DEFAULT '';

ALTER TABLE settings ADD COLUMN max_user_sessions_per_user integer NOT NULL DEFAULT 20;
