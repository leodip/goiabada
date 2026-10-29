-- Reverses migration 000069 (#676). DROP TABLE takes the indexes and the foreign keys with it.
--
-- Every client's introspection list is lost: no client introspects any resource's tokens until an
-- administrator lists them again.
DROP TABLE clients_introspection_resources;
