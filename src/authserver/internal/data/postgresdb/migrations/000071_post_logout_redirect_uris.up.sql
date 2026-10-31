-- A client's sign-out redirect URIs (#147 decision 2). See the sqlite migration of the same number
-- for why and for the six questions. PostgreSQL compares strings byte-wise, so uri needs no
-- collation pin; it is 2048 wide, as redirect_uris.uri is.
CREATE TABLE post_logout_redirect_uris (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP(6),
    uri VARCHAR(2048) NOT NULL,
    client_id BIGINT NOT NULL,
    CONSTRAINT fk_clients_post_logout_redirect_uris FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);
