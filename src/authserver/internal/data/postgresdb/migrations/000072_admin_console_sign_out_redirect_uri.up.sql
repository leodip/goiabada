-- The admin console's base URL moves from its client's redirect URIs to its sign-out redirect URIs
-- (#147 decision 8). See the sqlite migration of the same number for which rows move and why.
-- PostgreSQL compares uri byte-wise, so = is the exact match.
INSERT INTO post_logout_redirect_uris (created_at, uri, client_id)
SELECT bare.created_at, bare.uri, bare.client_id
  FROM redirect_uris AS bare
 INNER JOIN clients ON clients.id = bare.client_id
 WHERE clients.client_identifier = 'admin-console-client'
   AND EXISTS (SELECT 1 FROM redirect_uris AS callback
                WHERE callback.client_id = bare.client_id
                  AND callback.uri = bare.uri || '/auth/callback');

DELETE FROM redirect_uris AS bare
 USING clients
 WHERE clients.id = bare.client_id
   AND clients.client_identifier = 'admin-console-client'
   AND EXISTS (SELECT 1 FROM redirect_uris AS callback
                WHERE callback.client_id = bare.client_id
                  AND callback.uri = bare.uri || '/auth/callback');
