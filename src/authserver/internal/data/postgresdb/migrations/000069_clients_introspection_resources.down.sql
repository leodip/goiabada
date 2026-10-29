-- Reverses migration 000069 (#676). See the sqlite migration of the same number for what is lost:
-- every client's introspection list.
DROP TABLE clients_introspection_resources;
