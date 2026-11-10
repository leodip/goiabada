-- Reverses migration 000090 (#812): drops every client's brand. The index goes first, which SQLite
-- requires before DROP COLUMN.
DROP INDEX idx_clients_brand_id;
ALTER TABLE clients DROP COLUMN brand_id;
