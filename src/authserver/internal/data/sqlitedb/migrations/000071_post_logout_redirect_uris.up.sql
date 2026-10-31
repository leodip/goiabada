-- A client's sign-out redirect URIs (#147 decision 2): the addresses a sign-out may send the browser
-- back to, as OpenID Connect RP-Initiated Logout 1.0 calls post_logout_redirect_uri. They are kept
-- apart from redirect_uris, so registering a sign-out landing page never makes it a place an
-- authorization code can be delivered, and no sign-in reader of redirect_uris changes.
--
-- The six questions a migration answers: (1) all four engines. (2) uri is pinned
-- case-sensitive and is 2048 wide, as redirect_uris.uri is. (3) The lookup of the clients holding a
-- URI compares it with =, so the data layer compares the rows it got back against the URI it asked
-- for in Go. (4) No unique index, as redirect_uris has none: a list save refuses a duplicate, and the
-- column is too wide to index whole on MySQL and SQL Server. (5) No existing row changes meaning, and
-- nothing is backfilled: every client's list starts empty. (6) Each schema.golden gains the table.
--
-- The table mirrors redirect_uris on each engine: the same columns, the same cascade from clients,
-- and the same index on client_id, which is MySQL's foreign-key index and none elsewhere.
CREATE TABLE post_logout_redirect_uris (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    uri TEXT NOT NULL,
    client_id INTEGER NOT NULL,
    CONSTRAINT fk_clients_post_logout_redirect_uris FOREIGN KEY (client_id) REFERENCES clients (id) ON DELETE CASCADE
);
