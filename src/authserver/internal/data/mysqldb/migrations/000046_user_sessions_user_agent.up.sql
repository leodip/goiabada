-- The raw User-Agent header on the session row (#281). See the sqlite migration of the same number
-- for what the column holds, why it and ip_address are the "same device" key from here, and why
-- pre-upgrade rows reading '' is accepted rather than backfilled.
--
-- No COLLATE clause: user_sessions is declared utf8mb4_0900_as_cs and a column added without one
-- inherits the table's, which is the case-sensitive collation the sweep's comparison needs. The
-- width matches codes.user_agent.
ALTER TABLE `user_sessions` ADD COLUMN `user_agent` varchar(512) NOT NULL DEFAULT '';
