-- Migration 000087 down: drop a client's "Require DPoP for token requests", and every setting made
-- since with it. Nothing indexes or constrains the column, which is SQLite's requirement before DROP
-- COLUMN.
ALTER TABLE clients DROP COLUMN dpop_bound_access_tokens;
