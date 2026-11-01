-- Reverses migration 000077 (#622). Every record of what users accepted is lost, so every user is
-- asked again at their next sign-in.
DROP TABLE legal_document_acceptances;
