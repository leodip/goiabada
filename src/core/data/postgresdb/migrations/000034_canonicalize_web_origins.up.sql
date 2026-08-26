-- Web origins become the exact string a browser sends in an Origin header, and
-- the table starts saying that a client may list a given origin once (#250). See
-- the sqlite migration of the same number for why the rows need repairing, why
-- the order of the six steps is load-bearing, why the set repaired here is
-- exactly the set urlutil.CanonicalOrigin accepts, and why the delete lists what
-- is definitely wrong instead of whitelisting host characters.
--
-- What differs on this engine:
--   strpos(haystack, needle) replaces instr(), same argument order.
--   substr() clamps a negative start to the beginning of the string here rather
--   than counting from the right as SQLite does, so the last character is read
--   with right() and never with a negative offset. That difference is silent:
--   substr(x, -1) returns the whole string here, so a test written the SQLite way
--   would quietly compare the wrong thing.
--   ~ replaces GLOB and the rtrim-with-a-character-set trick, so the dotted quad
--   and the "last label is a number" test are each one expression.
UPDATE web_origins SET origin = btrim(origin);
UPDATE web_origins SET origin = lower(origin);

-- Everything from the first '/', '?' or '#' after the authority, at the scheme's
-- known prefix length. The 1000000 sentinel is what makes least() usable:
-- strpos() reports 0 for absent, which would win against a genuine position.
UPDATE web_origins
   SET origin = substr(origin, 1, 7 + least(
         coalesce(nullif(strpos(substr(origin, 8), '/'), 0), 1000000),
         coalesce(nullif(strpos(substr(origin, 8), '?'), 0), 1000000),
         coalesce(nullif(strpos(substr(origin, 8), '#'), 0), 1000000)) - 1)
 WHERE origin LIKE 'http://%'
   AND (strpos(substr(origin, 8), '/') > 0
     OR strpos(substr(origin, 8), '?') > 0
     OR strpos(substr(origin, 8), '#') > 0);

UPDATE web_origins
   SET origin = substr(origin, 1, 8 + least(
         coalesce(nullif(strpos(substr(origin, 9), '/'), 0), 1000000),
         coalesce(nullif(strpos(substr(origin, 9), '?'), 0), 1000000),
         coalesce(nullif(strpos(substr(origin, 9), '#'), 0), 1000000)) - 1)
 WHERE origin LIKE 'https://%'
   AND (strpos(substr(origin, 9), '/') > 0
     OR strpos(substr(origin, 9), '?') > 0
     OR strpos(substr(origin, 9), '#') > 0);

-- The colon count is a correctness guard rather than an optimisation: exactly
-- two colons means the authority holds exactly one, and stripping a default port
-- off a two-port authority would turn a row the delete below removes into a live
-- origin it keeps. The sqlite file carries the full reasoning (#250).
UPDATE web_origins SET origin = substr(origin, 1, char_length(origin) - 3)
 WHERE origin LIKE 'http://%:80'
   AND char_length(origin) - char_length(replace(origin, ':', '')) = 2;
UPDATE web_origins SET origin = substr(origin, 1, char_length(origin) - 4)
 WHERE origin LIKE 'https://%:443'
   AND char_length(origin) - char_length(replace(origin, ':', '')) = 2;

-- Over-long first. `origin` is character varying(256) here, so this is inert on
-- this engine; it is carried by all four files so they stay readable side by
-- side, and it is what removes sqlite's over-long rows, where the column is TEXT
-- (#250 decision 14b).
DELETE FROM web_origins WHERE char_length(origin) > 256;

-- Then every row that is still not exactly a canonical origin.
DELETE FROM web_origins WHERE id IN (
  SELECT id FROM (
    SELECT id, authority, colon_at,
           CASE WHEN colon_at > 0 THEN substr(authority, 1, colon_at - 1)
                ELSE authority END AS host,
           CASE WHEN colon_at > 0 THEN substr(authority, colon_at + 1)
                ELSE '' END AS port
      FROM (
        SELECT id, authority, strpos(authority, ':') AS colon_at
          FROM (
            SELECT id,
                   CASE WHEN origin LIKE 'https://%' THEN substr(origin, 9)
                        WHEN origin LIKE 'http://%'  THEN substr(origin, 8)
                   END AS authority
              FROM web_origins
          ) AS a
      ) AS b
  ) AS c
  WHERE authority IS NULL
     OR authority = ''
     OR authority ~ '[^ -~]'
     OR strpos(authority, ' ') > 0
     OR strpos(authority, '@') > 0
     OR strpos(authority, '[') > 0
     OR strpos(authority, ']') > 0
     OR strpos(authority, '%') > 0
     OR strpos(authority, '\') > 0
     OR strpos(authority, '^') > 0
     OR strpos(authority, '|') > 0
     OR strpos(authority, '<') > 0
     OR strpos(authority, '>') > 0
     OR strpos(authority, '#') > 0
     OR strpos(authority, '/') > 0
     OR strpos(authority, '?') > 0
     OR char_length(authority) - char_length(replace(authority, ':', '')) > 1
     OR (colon_at > 0 AND (port = ''
                        OR char_length(port) > 5
                        OR port ~ '[^0-9]'
                        OR (char_length(port) > 1 AND left(port, 1) = '0')
                        OR (char_length(port) = 5 AND port > '65535')))
     OR host = ''
     OR left(host, 1) = '.'
     OR strpos(host, '..') > 0
     -- A host that ends in an IPv4 number is kept only when it already is a
     -- strict dotted quad. The trailing dot is folded into both expressions as an
     -- optional '[.]?' rather than stripped first, since a browser drops it when
     -- the host parses as IPv4.
     OR ((host ~ '(^|[.])[0-9]+[.]?$' OR host ~ '(^|[.])0x[0-9a-f]*[.]?$')
         AND host !~ '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])([.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}$')
);

-- The duplicates the canonicalization has just created. MIN(id) keeps the
-- earliest registration, since the survivors are byte-identical and created_at is
-- all that distinguishes them.
DELETE FROM web_origins
 WHERE id NOT IN (SELECT id FROM (SELECT MIN(id) AS id FROM web_origins GROUP BY origin, client_id) AS keep);

CREATE UNIQUE INDEX idx_web_origins_origin_client ON web_origins(origin, client_id);
