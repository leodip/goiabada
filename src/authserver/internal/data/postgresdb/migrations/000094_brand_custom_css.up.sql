-- A brand's custom CSS (#816 decision 4). See the sqlite migration of the same number for why and
-- for the six questions. PostgreSQL compares strings byte-wise, so the column needs no collation
-- pin.
ALTER TABLE brands ADD COLUMN custom_css TEXT NOT NULL DEFAULT '';
