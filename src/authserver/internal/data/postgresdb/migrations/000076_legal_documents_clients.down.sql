-- Reverses migration 000076 (#622). Every document applies to all apps again, and the selected
-- apps are lost.
DROP TABLE legal_documents_clients;
ALTER TABLE legal_documents DROP COLUMN applies_to_all_apps;
