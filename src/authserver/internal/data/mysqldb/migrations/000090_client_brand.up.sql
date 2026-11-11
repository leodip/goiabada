-- A client's brand (#812 decision 1). See the sqlite migration of the same number for why and for
-- the six questions. The index is named and created before the key, so InnoDB uses it for the
-- foreign key and creates none of its own.
ALTER TABLE `clients` ADD COLUMN `brand_id` bigint unsigned NULL;
CREATE INDEX `idx_clients_brand_id` ON `clients`(`brand_id`);
ALTER TABLE `clients` ADD CONSTRAINT `fk_clients_brand`
    FOREIGN KEY (`brand_id`) REFERENCES `brands` (`id`);
