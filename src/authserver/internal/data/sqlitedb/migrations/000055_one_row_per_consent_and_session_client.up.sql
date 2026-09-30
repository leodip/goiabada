-- One consent per user and client, and one association per session and client (#249, #115, #437).
--
-- Neither table had a unique key over the pair it is looked up by. The consent screen's save reads
-- the row for a user and client and then creates it or rewrites it, and a session's bump reads the
-- session's associations and then inserts the one for a client it lacks. Two requests that overlap
-- can each read "absent" and both insert, leaving two rows for one pair, and every reader then
-- takes whichever row the engine returns first: a consent the user narrowed can come back as the
-- wider one, and a session lists a client twice. The writers now run in a transaction that reruns
-- once when it loses the key; these two indexes are what make the loss detectable, and what make
-- "one row per pair" something the schema says rather than something the code hopes.
--
-- THE SWEEP. A deployment may already carry a duplicate, so each index is preceded by a DELETE of
-- every row but one per pair. A failed migration stops startup and leaves the schema version dirty,
-- and a deployment that cannot start cannot be repaired through the product, so a duplicate is
-- swept and not refused.
--
-- Consents keep the row with the latest updated_at, and the highest id breaks a tie. The highest id
-- alone would be the most recently CREATED row, not the most recently SAVED one: the consent
-- screen's save rewrites the row it reads in place, keeping its id and setting updated_at, so a
-- lower-id duplicate saved later holds the user's latest answer, and a refresh that consults the
-- consent would be handed the scope the user had already removed. The winning
-- row keeps its scope, granted_at and every other column as they are. A NULL updated_at counts as
-- the oldest: the writers always set it, but the column is nullable, and a comparison that met a
-- NULL would keep no row for its pair, or two. The two-level shape, the latest time per pair and
-- then the highest id among the rows at that time, is what keeps the derived table aggregated: MySQL
-- refuses a DELETE whose subquery names the table being deleted from unless that subquery is
-- materialized, and an aggregate is what stops it being merged into the statement.
--
-- Session associations keep the lowest id. Two rows for one pair are the same fact twice, and a
-- row's columns are times the next bump overwrites, so nothing distinguishes them that is worth
-- choosing by; the oldest is the one other rows may already have been written against.
--
-- The six questions (reference/migrations.md 6): (1) all four engines. (2) No new column: both
-- keys are integer ids. (3) No new lookup compares a string with =: the pairs are matched on
-- integers. (4) Uniqueness is added over integer ids only, after the sweep, so it cannot fail on
-- existing data; the down migration drops both indexes and cannot restore a row the sweep deleted.
-- (5) An existing duplicate is deleted as described above, and nothing else: today the consent that
-- governs is whichever row the engine returns, so keeping the last saved makes it deterministic,
-- and no row an operator can sign in as is touched. (6) Each schema.golden gains the two unique
-- indexes.
--
-- The indexes are named for their columns as idx_user_session_clients_client_id (000044) is. The
-- existing foreign-key indexes stay: they serve the lookups by one column, these serve the pair.
DELETE FROM user_consents
 WHERE id NOT IN (
    SELECT id FROM (
        SELECT MAX(c.id) AS id
          FROM user_consents c
          JOIN (SELECT user_id, client_id, MAX(updated_at) AS last_saved
                  FROM user_consents GROUP BY user_id, client_id) m
            ON m.user_id = c.user_id AND m.client_id = c.client_id
           AND (c.updated_at = m.last_saved OR (c.updated_at IS NULL AND m.last_saved IS NULL))
         GROUP BY c.user_id, c.client_id
    ) AS keep);

CREATE UNIQUE INDEX `idx_user_consents_user_id_client_id` ON `user_consents`(`user_id`, `client_id`);

DELETE FROM user_session_clients
 WHERE id NOT IN (SELECT id FROM (SELECT MIN(id) AS id FROM user_session_clients GROUP BY user_session_id, client_id) AS keep);

CREATE UNIQUE INDEX `idx_user_session_clients_user_session_id_client_id` ON `user_session_clients`(`user_session_id`, `client_id`);
