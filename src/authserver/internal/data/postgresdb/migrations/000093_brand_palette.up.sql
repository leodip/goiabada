-- A brand's custom palette (#815 decision 3). See the sqlite migration of the same number for why
-- and for the six questions. PostgreSQL compares strings byte-wise, so the column needs no
-- collation pin.
ALTER TABLE brands ADD COLUMN palette TEXT NULL;
