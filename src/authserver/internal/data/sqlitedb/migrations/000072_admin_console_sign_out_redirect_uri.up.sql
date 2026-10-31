-- The admin console's base URL moves from its client's redirect URIs to its sign-out redirect URIs
-- (#147 decision 8). A sign-out now returns only to a sign-out redirect URI, so without the move the
-- console's own Sign out would fail on every upgrade; and left among the redirect URIs, the bare URL
-- would stay a place an authorization code can be sent that the console never signs in through.
--
-- For the client admin-console-client, a redirect URI moves when that URI followed by /auth/callback
-- is also one of the client's redirect URIs: the shape the first start writes, which catches the old
-- and the new URL after a URL change made as the docs describe. Each such row is copied into
-- post_logout_redirect_uris with its created_at, then deleted from redirect_uris. Nothing else moves:
-- not a row an operator added for another purpose, and not another client's identical pair. A bare
-- URL that isn't there moves nothing, and the console's sign-out then fails until an operator adds
-- it on the Sign-out redirect URIs tab.
--
-- The match is exact: uri compares byte-wise here and on PostgreSQL, and the MySQL and SQL Server
-- migrations compare the bytes, since their collations pad or fold. The down migration moves the
-- rows back.
INSERT INTO post_logout_redirect_uris (created_at, uri, client_id)
SELECT bare.created_at, bare.uri, bare.client_id
  FROM redirect_uris AS bare
 INNER JOIN clients ON clients.id = bare.client_id
 WHERE clients.client_identifier = 'admin-console-client'
   AND EXISTS (SELECT 1 FROM redirect_uris AS callback
                WHERE callback.client_id = bare.client_id
                  AND callback.uri = bare.uri || '/auth/callback');

DELETE FROM redirect_uris
 WHERE id IN (SELECT bare.id
                FROM redirect_uris AS bare
               INNER JOIN clients ON clients.id = bare.client_id
               WHERE clients.client_identifier = 'admin-console-client'
                 AND EXISTS (SELECT 1 FROM redirect_uris AS callback
                              WHERE callback.client_id = bare.client_id
                                AND callback.uri = bare.uri || '/auth/callback'));
