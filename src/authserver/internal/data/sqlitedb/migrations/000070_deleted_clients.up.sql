-- A deleted client's identifier and the moment it was deleted (#676 decision 6). An access token
-- names its client only by client_id, which a new client may take once the old one is deleted, so
-- the access-token liveness check refuses a token issued before its client's created_at second. A
-- token issued in that very second cannot be told apart by its iat, which has whole seconds, so the
-- check reads this row for it and refuses it when the identifier was deleted in or after that
-- second: the token was the deleted client's, or the new client was created in the second its
-- predecessor was deleted, and either way the check fails closed. A token of the client
-- credentials grant or the implicit flow has no grant whose deletion would otherwise end it.
--
-- The six questions (reference/migrations.md 6): (1) all four engines. (2) client_identifier is
-- pinned case-sensitive and is 40 wide, as clients.client_identifier is. (3) The lookup compares
-- the identifier with =, so the data layer compares the row it got back against the identifier it
-- asked for in Go. (4) The identifier is the primary key: a deletion replaces the row of an earlier
-- deletion of the same identifier, since only the latest can follow a client that exists now. (5)
-- No existing row changes meaning, and nothing is backfilled: a client deleted before this
-- migration was deleted at least a second before any client created after it. (6) Each
-- schema.golden gains the table.
--
-- Rows are kept, one per identifier ever deleted: a row matters while a token issued in the second
-- of its identifier's next creation can live, which no column here bounds.
CREATE TABLE deleted_clients (
    client_identifier TEXT NOT NULL PRIMARY KEY,
    deleted_at DATETIME NOT NULL
);
