-- Index user_session_clients(client_id) (#139). See the sqlite migration of the same number
-- for what reads it and why SQL Server is the engine that makes it necessary.
CREATE INDEX idx_user_session_clients_client_id
    ON user_session_clients(client_id);
