-- A deleted client's identifier and the moment it was deleted (#676 decision 6). See the sqlite
-- migration of the same number for why, for the six questions and for why rows are kept.
-- PostgreSQL compares strings byte-wise, so the identifier needs no collation pin.
CREATE TABLE deleted_clients (
    client_identifier character varying(40) NOT NULL PRIMARY KEY,
    deleted_at timestamp(6) without time zone NOT NULL
);
