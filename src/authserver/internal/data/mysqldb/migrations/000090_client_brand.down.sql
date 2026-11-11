-- Reverses migration 000090 (#812). The foreign key goes before its index, which MySQL refuses to
-- drop while the key uses it.
ALTER TABLE `clients` DROP FOREIGN KEY `fk_clients_brand`;
DROP INDEX `idx_clients_brand_id` ON `clients`;
ALTER TABLE `clients` DROP COLUMN `brand_id`;
