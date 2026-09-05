-- Index user_session_clients(client_id) (#139).
--
-- What reads it: DeleteClient now takes the client's row and then reads every association
-- naming that client, so it can take those sessions' rows before its cascade wants them.
-- That read is the client deletion's own path and runs once per deletion, so the scan is
-- not what makes the index worth a migration.
--
-- The reason is SQL Server, whose READ COMMITTED is lock-based: the full table scan this
-- replaces takes shared locks across the association rows of OTHER clients' sessions on its
-- way past them, so the deletion would block on rows it has no interest in. A change whose
-- whole purpose is to remove a blocking edge must not introduce one.
--
-- Added on the three engines that lack it; MySQL already has it, under the name InnoDB gave
-- the foreign key's index, and its file of this number renames it to match.
--
-- Non-unique: a session can name several clients and a client is named by many sessions.
-- #249 is the unique constraint on the PAIR, which is a different index and a different
-- question.
CREATE INDEX idx_user_session_clients_client_id
    ON user_session_clients(client_id);
