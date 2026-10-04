-- Reverses migration 000057 (#394). See the sqlite migration of the same number for what is lost:
-- every count, which refills every shared credential budget once.
DROP TABLE `rate_limit_counters`;
