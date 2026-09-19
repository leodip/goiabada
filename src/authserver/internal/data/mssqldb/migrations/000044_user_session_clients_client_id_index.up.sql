-- Index user_session_clients(client_id) (#139). See the sqlite migration of the same number
-- for what reads it. This is the engine that makes it necessary: READ COMMITTED here is
-- lock-based, so the scan it replaces took shared locks across other clients' association
-- rows on its way past them.
CREATE INDEX [idx_user_session_clients_client_id]
    ON [user_session_clients]([client_id]);
