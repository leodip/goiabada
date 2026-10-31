-- The admin console's base URL moves from its client's redirect URIs to its sign-out redirect URIs
-- (#147 decision 8). See the sqlite migration of the same number for which rows move and why.
--
-- The partner is compared as bytes: the column's collation pads trailing spaces for = and folds a
-- composed accent onto its decomposed spelling.
INSERT INTO [post_logout_redirect_uris] ([created_at], [uri], [client_id])
SELECT [bare].[created_at], [bare].[uri], [bare].[client_id]
  FROM [redirect_uris] AS [bare]
 INNER JOIN [clients] ON [clients].[id] = [bare].[client_id]
 WHERE [clients].[client_identifier] = N'admin-console-client'
   AND EXISTS (SELECT 1 FROM [redirect_uris] AS [callback]
                WHERE [callback].[client_id] = [bare].[client_id]
                  AND CAST([callback].[uri] AS VARBINARY(MAX)) = CAST([bare].[uri] + N'/auth/callback' AS VARBINARY(MAX)));

DELETE [bare]
  FROM [redirect_uris] AS [bare]
 INNER JOIN [clients] ON [clients].[id] = [bare].[client_id]
 WHERE [clients].[client_identifier] = N'admin-console-client'
   AND EXISTS (SELECT 1 FROM [redirect_uris] AS [callback]
                WHERE [callback].[client_id] = [bare].[client_id]
                  AND CAST([callback].[uri] AS VARBINARY(MAX)) = CAST([bare].[uri] + N'/auth/callback' AS VARBINARY(MAX)));
