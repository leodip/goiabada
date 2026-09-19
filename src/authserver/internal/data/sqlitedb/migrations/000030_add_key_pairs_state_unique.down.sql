-- Dropping the index cannot restore the rows the up migration swept. They are gone,
-- and rolling back returns the table to accepting duplicates rather than to the
-- contents it had before (#251).
DROP INDEX `idx_key_pairs_state`;
