-- Migration 000063 down: drop both columns. A database migrated forward again reads '' as every
-- session's device identifier, as a session stored before the upgrade does, and 20 as the cap,
-- whatever an administrator had set.
ALTER TABLE user_sessions DROP COLUMN device_id;

ALTER TABLE settings DROP COLUMN max_user_sessions_per_user;
