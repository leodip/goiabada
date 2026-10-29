-- A deleted client's identifier and the moment it was deleted (#676 decision 6). See the sqlite
-- migration of the same number for why, for the six questions and for why rows are kept.
--
-- client_identifier is varchar(40), the width of clients.client_identifier, and the table is pinned
-- to the case- and accent-sensitive collation every table here carries (#283), so the primary key
-- means what it says.
CREATE TABLE `deleted_clients` (
    `client_identifier` varchar(40) NOT NULL,
    `deleted_at` datetime(6) NOT NULL,
    PRIMARY KEY (`client_identifier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
