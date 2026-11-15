-- Migration 000096 down: drop the token_endpoint_auth_method clients registered, and every method
-- stored since with it.
ALTER TABLE `clients` DROP COLUMN `token_endpoint_auth_method`;
