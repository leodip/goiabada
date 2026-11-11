-- A client's brand (#812 decision 1): clients.brand_id is the brand the client's pages are drawn
-- in, or NULL to follow whichever brand is the default.
--
-- The six questions a migration answers: (1) all four engines. (2) No string column. (3) Nothing
-- is compared. (4) A foreign key to brands(id) with no cascade, so the engine refuses deleting a
-- brand a client names; the data layer's deletion puts those clients back on the default first,
-- under the settings row's lock, and the key is the backstop. (5) Nothing is backfilled: every
-- existing client starts on NULL, the default it was drawn in until now. (6) Each schema.golden
-- gains the column, its foreign key and its index.
--
-- The index serves the deletion's move and the engine's own check of the key when a brand is
-- deleted. The previous release never names the column, so a replica of it still serving during a
-- rolling upgrade keeps working; a brand deletion it makes while a client uses the brand is refused
-- by the key. The down migration drops the column, and every assignment made since with it.
ALTER TABLE clients ADD COLUMN brand_id INTEGER NULL
    CONSTRAINT fk_clients_brand REFERENCES brands (id);
CREATE INDEX idx_clients_brand_id ON clients (brand_id);
