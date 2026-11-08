-- Migration 000087 down: drop a client's "Require DPoP for token requests", and every setting made
-- since with it.
ALTER TABLE `clients` DROP COLUMN `dpop_bound_access_tokens`;
