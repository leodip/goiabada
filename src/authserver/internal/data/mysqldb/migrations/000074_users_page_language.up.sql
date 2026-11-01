-- The language a user chose for Goiabada's own pages and emails (#631 decision 8). See the sqlite
-- migration of the same number for what the column holds and why existing rows land on ''.
--
-- No COLLATE clause: users is declared utf8mb4_0900_as_cs and a column added without one inherits
-- the table's, the case-sensitive collation every string column carries (#283). 32 wide, as locale is.
ALTER TABLE `users` ADD COLUMN `page_language` varchar(32) NOT NULL DEFAULT '';
