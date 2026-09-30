-- One consent per user and client, and one association per session and client (#249, #115, #437).
-- See the sqlite migration of the same number for why, for which row the sweep keeps, and for the
-- six questions.
--
-- No EXEC and no named default constraint here: this migration adds no column, so nothing in the
-- batch names an identifier the same batch has just created.
DELETE FROM [user_consents]
 WHERE [id] NOT IN (
    SELECT [id] FROM (
        SELECT MAX(c.[id]) AS [id]
          FROM [user_consents] c
          JOIN (SELECT [user_id], [client_id], MAX([updated_at]) AS [last_saved]
                  FROM [user_consents] GROUP BY [user_id], [client_id]) m
            ON m.[user_id] = c.[user_id] AND m.[client_id] = c.[client_id]
           AND (c.[updated_at] = m.[last_saved] OR (c.[updated_at] IS NULL AND m.[last_saved] IS NULL))
         GROUP BY c.[user_id], c.[client_id]
    ) AS keep);

CREATE UNIQUE INDEX [idx_user_consents_user_id_client_id] ON [user_consents]([user_id], [client_id]);

DELETE FROM [user_session_clients]
 WHERE [id] NOT IN (SELECT [id] FROM (SELECT MIN([id]) AS [id] FROM [user_session_clients] GROUP BY [user_session_id], [client_id]) AS keep);

CREATE UNIQUE INDEX [idx_user_session_clients_user_session_id_client_id] ON [user_session_clients]([user_session_id], [client_id]);
