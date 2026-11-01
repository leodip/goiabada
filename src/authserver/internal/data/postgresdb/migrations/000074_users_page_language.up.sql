-- The language a user chose for Goiabada's own pages and emails (#631 decision 8). See the sqlite
-- migration of the same number for what the column holds and why existing rows land on ''.
--
-- 32 wide, as locale is. PostgreSQL compares strings byte-wise, so it needs no collation pin.
ALTER TABLE users ADD COLUMN page_language varchar(32) NOT NULL DEFAULT '';
