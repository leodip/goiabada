-- Migration 000096 down: drop the token_endpoint_auth_method clients registered, and every method
-- stored since with it. Nothing indexes or constrains the column, which is SQLite's requirement
-- before DROP COLUMN.
ALTER TABLE clients DROP COLUMN token_endpoint_auth_method;
