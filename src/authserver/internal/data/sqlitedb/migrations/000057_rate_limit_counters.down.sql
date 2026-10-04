-- Reverses migration 000057 (#394). DROP TABLE takes the primary key and the index with it.
--
-- Every count is lost, which refills every shared credential budget once: the same thing a
-- restart did to the in-memory counts before the table existed.
DROP TABLE rate_limit_counters;
