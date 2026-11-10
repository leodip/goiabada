-- Reverses migration 000090 (#812).
DROP INDEX idx_clients_brand_id;
ALTER TABLE clients DROP CONSTRAINT fk_clients_brand;
ALTER TABLE clients DROP COLUMN brand_id;
