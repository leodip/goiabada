-- A session's device identifier and the per-user session cap (#564 decision 11). See the sqlite
-- migration of the same number for what the two columns hold, and why each carries a default rather
-- than a backfill.
--
-- No COLLATE clause: user_sessions is declared utf8mb4_0900_as_cs and a column added without one
-- inherits the table's. 64 characters is a SHA-256 in hex.
ALTER TABLE `user_sessions` ADD COLUMN `device_id` varchar(64) NOT NULL DEFAULT '';

ALTER TABLE `settings` ADD COLUMN `max_user_sessions_per_user` int NOT NULL DEFAULT 20;
