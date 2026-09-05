-- Index user_session_clients(client_id) under the same name on all four engines (#139).
--
-- What reads it: DeleteClient now takes the client's row and then reads every association
-- naming that client, so it can take those sessions' rows before its cascade wants them.
-- On SQL Server, whose READ COMMITTED is lock-based, the full scan that read would otherwise
-- be takes shared locks across the association rows of OTHER clients' sessions on its way
-- past them, and a change whose whole purpose is to remove a blocking edge must not
-- introduce one. The other three engines get a CREATE INDEX.
--
-- MySQL alone already has the index and needs only its name. InnoDB requires an index over a
-- foreign key's columns, so the initial migration declared KEY `fk_user_session_clients_client`
-- inline to satisfy the reference to `clients`; it covers exactly this column. Leaving the
-- name alone would put MySQL out of line with the other three under #284's name comparison,
-- and would make a later `DROP INDEX idx_user_session_clients_client_id` succeed on three
-- engines and fail here, which is the failure that comparison exists to catch.
--
-- RENAME INDEX is in-place metadata on InnoDB and is accepted for an index a foreign key
-- depends on, which DROP INDEX would not be. This is 000042's idiom, for the same reason.
ALTER TABLE `user_session_clients`
    RENAME INDEX `fk_user_session_clients_client` TO `idx_user_session_clients_client_id`;
