-- Reverses migration 000055 (#249, #115, #437). Dropping an index cannot restore the rows the up
-- migration swept: they are gone, and rolling back returns both tables to accepting two rows for
-- one pair rather than to the contents they had before.
DROP INDEX `idx_user_session_clients_user_session_id_client_id`;
DROP INDEX `idx_user_consents_user_id_client_id`;
