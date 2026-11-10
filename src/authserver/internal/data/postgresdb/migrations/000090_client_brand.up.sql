-- A client's brand (#812 decision 1). See the sqlite migration of the same number for why and for
-- the six questions.
ALTER TABLE clients ADD COLUMN brand_id BIGINT NULL;
ALTER TABLE clients ADD CONSTRAINT fk_clients_brand
    FOREIGN KEY (brand_id) REFERENCES brands (id);
CREATE INDEX idx_clients_brand_id ON clients (brand_id);
