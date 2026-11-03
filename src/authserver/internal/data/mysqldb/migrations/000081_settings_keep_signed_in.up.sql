-- The "Keep users signed in after the browser closes" setting (#743 decisions 3 and 4). See the
-- sqlite migration of the same number for what the column holds, and why it defaults to 'ask'.
--
-- No COLLATE clause: settings is declared utf8mb4_0900_as_cs and a column added without one
-- inherits the table's. The type is the SMTP encryption's, the row's other lower-case enumeration.
ALTER TABLE `settings` ADD COLUMN `keep_signed_in` varchar(16) NOT NULL DEFAULT 'ask';
