-- Reverses migration 000055 (#249, #115, #437). See the sqlite migration of the same number for
-- what is not restored: the rows the up migration swept.
DROP INDEX [idx_user_session_clients_user_session_id_client_id] ON [user_session_clients];
DROP INDEX [idx_user_consents_user_id_client_id] ON [user_consents];
