-- Reverses migration 000072 (#147): each of the admin console's sign-out redirect URIs whose value
-- followed by /auth/callback is one of its redirect URIs goes back to its redirect URIs.
INSERT INTO redirect_uris (created_at, uri, client_id)
SELECT bare.created_at, bare.uri, bare.client_id
  FROM post_logout_redirect_uris AS bare
 INNER JOIN clients ON clients.id = bare.client_id
 WHERE clients.client_identifier = 'admin-console-client'
   AND EXISTS (SELECT 1 FROM redirect_uris AS callback
                WHERE callback.client_id = bare.client_id
                  AND callback.uri = bare.uri || '/auth/callback');

DELETE FROM post_logout_redirect_uris AS bare
 USING clients
 WHERE clients.id = bare.client_id
   AND clients.client_identifier = 'admin-console-client'
   AND EXISTS (SELECT 1 FROM redirect_uris AS callback
                WHERE callback.client_id = bare.client_id
                  AND callback.uri = bare.uri || '/auth/callback');
