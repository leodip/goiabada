-- Dropping the index cannot restore the rows the up migration swept (#251).
DROP INDEX `idx_key_pairs_state` ON `key_pairs`;
