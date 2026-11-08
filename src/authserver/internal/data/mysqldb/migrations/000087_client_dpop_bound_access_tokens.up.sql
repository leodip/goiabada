-- A client's "Require DPoP for token requests" (#42 decision 12). See the sqlite migration of the
-- same number for what the column holds and why nothing is backfilled.
ALTER TABLE `clients` ADD COLUMN `dpop_bound_access_tokens` tinyint(1) NOT NULL DEFAULT 0;
