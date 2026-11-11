-- Reverses migration 000090 (#812). SQL Server refuses dropping a column while a constraint or an
-- index names it, so both go first.
ALTER TABLE [clients] DROP CONSTRAINT [fk_clients_brand];
DROP INDEX [idx_clients_brand_id] ON [clients];
ALTER TABLE [clients] DROP COLUMN [brand_id];
