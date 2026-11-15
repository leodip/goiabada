-- The token_endpoint_auth_method a client registered through dynamic client registration (#708
-- decision 3). See the sqlite migration of the same number for what the column holds and why
-- nothing is backfilled.
--
-- No COLLATE clause: clients is declared utf8mb4_0900_as_cs, and a column added without one
-- inherits the table's, as website_url's has.
ALTER TABLE `clients` ADD COLUMN `token_endpoint_auth_method` varchar(64) NOT NULL DEFAULT '';
