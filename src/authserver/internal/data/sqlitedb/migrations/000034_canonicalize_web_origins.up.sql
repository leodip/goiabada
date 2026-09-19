-- Migration 000034: every web origin becomes the exact string a browser sends in
-- an Origin header, and the table starts saying that a client may list a given
-- origin once (#250).
--
-- WHY THE ROWS NEED REPAIRING. Until this release the Admin API validated a web
-- origin with url.ParseRequestURI plus an http/https scheme check, then stored it
-- lowercased and otherwise verbatim. MiddlewareCors compares the stored value to
-- the browser's Origin header with ==, and a browser sends
-- scheme "://" host [ ":" port ] and nothing else. So a stored value carrying a
-- trailing slash, a path, a query, a fragment or a default port has never matched
-- anything and never could. The failure is silent: the save returned 200, the
-- value appears in the list, and CORS simply fails with nothing explaining why.
--
-- ORDER IS LOAD-BEARING. Canonicalize, then delete what cannot be canonicalized,
-- then dedupe, then add the index. Canonicalizing is what creates the duplicates,
-- so the dedupe cannot come first, and deleting the unrepairable before the
-- dedupe keeps the dedupe from grouping rows that are about to go.
--
-- THE SET THIS REPAIRS IS THE SET THE WRITE PATH ACCEPTS, deliberately, and the
-- two have to move together. urlutil.CanonicalOrigin converts case, surrounding
-- whitespace, a trailing slash, a path, a query, a fragment and a default port,
-- and it REFUSES everything else a browser would serialize differently: a
-- non-ASCII host, userinfo, any IPv6 literal, a zone identifier, an empty,
-- leading-zero or out-of-range port, and a host that ends in an IPv4 number
-- without already being a strict dotted quad. It refuses them because SQL cannot
-- do punycode, IPv6 compression or IPv4 expansion, so a shape the endpoint
-- converted and this file could not would be a row left permanently dead, which
-- is the defect the whole change exists to remove. Widening one side without the
-- other reopens it.
--
-- WHICH DIRECTION AN ERROR IN THE DELETE COSTS MORE. Deleting a row
-- CanonicalOrigin would have accepted destroys a live CORS origin. Leaving a row
-- it would refuse leaves a row that was already dead. So the predicate below
-- lists what is definitely wrong rather than whitelisting host characters: a
-- whitelist of [a-z0-9.-] reads as tidier and would delete http://foo_bar, which
-- is unusual, legal, and works today.
--
-- The other three engines run the same ordered conjunction in the same order and
-- differ only in the character-class idiom. This file is the one they point at.

-- 1. Surrounding spaces, then case. Both unconditional rather than guarded by a
-- WHERE. SQL Server's default collation is case-insensitive, so there
-- `origin <> LOWER(origin)` is always false: a guard that reads as an
-- optimisation on three engines is a silent no-op on the fourth, and the four
-- files are meant to be read side by side.
--
-- Only spaces are trimmed, not every character CanonicalOrigin trims. A value
-- padded with a tab or a newline cannot have reached this table (url.Parse
-- refuses a control character, and the console sends new URL(v).origin), and as
-- stored it has never matched an Origin header, so step 4 removing it removes
-- nothing that ever worked.
UPDATE web_origins SET origin = trim(origin);
UPDATE web_origins SET origin = lower(origin);

-- 2. Everything from the first '/', '?' or '#' after the authority. Two
-- statements with the scheme's known prefix length, 7 for http:// and 8 for
-- https://, rather than searching for the third '/': the prefix is known, and a
-- search that miscounts matches nothing SILENTLY, which is migration 000033's
-- recorded lesson.
--
-- The 1000000 sentinel is what makes min() usable: instr() reports 0 for absent,
-- which would win a min() against a genuine position.
UPDATE web_origins
   SET origin = substr(origin, 1, 7 + min(
         coalesce(nullif(instr(substr(origin, 8), '/'), 0), 1000000),
         coalesce(nullif(instr(substr(origin, 8), '?'), 0), 1000000),
         coalesce(nullif(instr(substr(origin, 8), '#'), 0), 1000000)) - 1)
 WHERE origin LIKE 'http://%'
   AND (instr(substr(origin, 8), '/') > 0
     OR instr(substr(origin, 8), '?') > 0
     OR instr(substr(origin, 8), '#') > 0);

UPDATE web_origins
   SET origin = substr(origin, 1, 8 + min(
         coalesce(nullif(instr(substr(origin, 9), '/'), 0), 1000000),
         coalesce(nullif(instr(substr(origin, 9), '?'), 0), 1000000),
         coalesce(nullif(instr(substr(origin, 9), '#'), 0), 1000000)) - 1)
 WHERE origin LIKE 'https://%'
   AND (instr(substr(origin, 9), '/') > 0
     OR instr(substr(origin, 9), '?') > 0
     OR instr(substr(origin, 9), '#') > 0);

-- 3. The default port, which a browser leaves out of the header entirely. The
-- pattern is anchored at both ends, so http://a.com:8080 is untouched: its last
-- three characters are '080', not ':80'.
--
-- THE COLON COUNT IS A CORRECTNESS GUARD, NOT AN OPTIMISATION. Step 2 has
-- already cut everything after the authority, so the only colons left are the
-- one in '://' and any inside the authority; exactly two means the authority
-- holds exactly one, which is the only shape that has a port to strip.
--
-- Without it this step is the one place in the file that can turn a row step 4
-- would have deleted into one it keeps. Stripping the trailing ':443' off
-- https://a.example:80:443 leaves https://a.example:80, a live and
-- browser-reachable origin that was never registered, and step 4 then finds a
-- single colon and a valid port and keeps it. CanonicalOrigin refuses that input
-- outright, because it splits the port at the LAST colon and so checks the host
-- 'a.example:80', where a colon is not an allowed domain code point. Step 4
-- splits at the FIRST colon instead and refuses the row on its second colon, so
-- removing that colon here is precisely what disarms it (#250).
UPDATE web_origins SET origin = substr(origin, 1, length(origin) - 3)
 WHERE origin LIKE 'http://%:80'
   AND length(origin) - length(replace(origin, ':', '')) = 2;
UPDATE web_origins SET origin = substr(origin, 1, length(origin) - 4)
 WHERE origin LIKE 'https://%:443'
   AND length(origin) - length(replace(origin, ':', '')) = 2;

-- 4. Delete what cannot be repaired, in two statements.
--
-- First the over-long. `origin` is TEXT here and 256 characters on the other
-- three engines, so only sqlite can hold a longer value at all; the statement is
-- carried by all four so the files stay readable side by side, and on the other
-- three it is inert. A standards-valid origin can reach 267 characters
-- (`https://` plus a 253-character host plus `:65535`), so this is a storage
-- limit rather than a fact about origins, and it is the same limit
-- HandleAPIClientWebOriginsPut refuses a new value against (#250 decision 14b).
-- Widening three columns four different ways inside a migration already doing
-- string surgery four different ways is the trade this declines.
DELETE FROM web_origins WHERE length(origin) > 256;

-- Then every row that is still not exactly a canonical origin. Such a row
-- has never matched an Origin header and no conversion above can reach it, so it
-- is the silent dead row this change exists to remove.
--
-- The derived tables exist to name authority, host and port once. Splitting the
-- port at the FIRST colon rather than the last, as CanonicalOrigin does, is
-- equivalent here because a second colon is refused outright two clauses below:
-- a host holding a colon is not an allowed domain code point, and an IPv6
-- literal is already refused by its brackets.
--
-- Two techniques carry the last clause, the IPv4 rule.
--   Padding the host to '.' || host || '.' makes "some label exceeds 255"
--   position-independent, so it is three patterns rather than nine (first,
--   middle and last label each needing their own anchoring), and the same for
--   the leading-zero test.
--   rtrim(h, '<digits>') strips trailing digits, so its result is empty exactly
--   when the whole host is digits and ends in '.' exactly when the last label
--   is. That is how this engine reads the last label without a regex or a
--   REVERSE, neither of which SQLite has.
DELETE FROM web_origins WHERE id IN (
  SELECT id FROM (
    SELECT id, authority, colon_at, host, port,
           rtrim(h2, '0123456789')       AS dig_tail,
           rtrim(h2, '0123456789abcdef') AS hex_tail
      FROM (
        SELECT id, authority, colon_at, host, port,
               -- A single trailing dot is a distinct host a browser serializes
               -- verbatim, so it is not part of the name when deciding whether
               -- the host ends in a number.
               CASE WHEN substr(host, -1) = '.'
                    THEN substr(host, 1, length(host) - 1)
                    ELSE host END AS h2
          FROM (
            SELECT id, authority, colon_at,
                   CASE WHEN colon_at > 0 THEN substr(authority, 1, colon_at - 1)
                        ELSE authority END AS host,
                   CASE WHEN colon_at > 0 THEN substr(authority, colon_at + 1)
                        ELSE '' END AS port
              FROM (
                SELECT id, authority, instr(authority, ':') AS colon_at
                  FROM (
                    SELECT id,
                           CASE WHEN origin LIKE 'https://%' THEN substr(origin, 9)
                                WHEN origin LIKE 'http://%'  THEN substr(origin, 8)
                           END AS authority
                      FROM web_origins
                  ) AS a
              ) AS b
          ) AS c
      ) AS d
  ) AS e
  WHERE authority IS NULL                                        -- scheme is neither http nor https
     OR authority = ''
     OR authority GLOB '*[^ -~]*'                                -- a control character, DEL, or non-ASCII
     OR instr(authority, ' ') > 0
     OR instr(authority, '@') > 0                                -- userinfo
     OR instr(authority, '[') > 0                                -- an IPv6 literal
     OR instr(authority, ']') > 0
     OR instr(authority, '%') > 0                                -- a zone identifier or any percent-escape
     OR instr(authority, '\') > 0
     OR instr(authority, '^') > 0
     OR instr(authority, '|') > 0
     OR instr(authority, '<') > 0
     OR instr(authority, '>') > 0
     OR instr(authority, '#') > 0
     OR instr(authority, '/') > 0
     OR instr(authority, '?') > 0
     OR length(authority) - length(replace(authority, ':', '')) > 1
     OR (colon_at > 0 AND (port = ''
                        OR length(port) > 5
                        OR port GLOB '*[^0-9]*'
                        -- '0443' and '443' are the same port to a browser but a
                        -- different string, so the leading zero is refused
                        -- rather than converted.
                        OR (length(port) > 1 AND substr(port, 1, 1) = '0')
                        -- Digits only and exactly five long, so the string
                        -- comparison is the numeric one.
                        OR (length(port) = 5 AND port > '65535')))
     OR host = ''
     OR substr(host, 1, 1) = '.'
     OR instr(host, '..') > 0
     -- A host that ends in an IPv4 number is re-serialized by the browser as a
     -- dotted quad, so it is kept only when it already is one: http://127.1,
     -- http://2130706433 and http://0x7f000001 all mean 127.0.0.1 to a browser
     -- and none of them is the string it sends.
     OR ((dig_tail = ''
          OR substr(dig_tail, -1) = '.'
          OR hex_tail = '0x'
          OR substr(hex_tail, -3) = '.0x')
         AND NOT (host NOT GLOB '*[^0-9.]*'
              AND length(host) - length(replace(host, '.', '')) = 3
              AND substr(host, 1, 1) <> '.'
              AND substr(host, -1) <> '.'
              AND instr(host, '..') = 0
              AND host NOT GLOB '*[0-9][0-9][0-9][0-9]*'
              AND ('.' || host || '.') NOT GLOB '*.0[0-9]*'
              AND ('.' || host || '.') NOT GLOB '*.[3-9][0-9][0-9].*'
              AND ('.' || host || '.') NOT GLOB '*.2[6-9][0-9].*'
              AND ('.' || host || '.') NOT GLOB '*.25[6-9].*'))
);

-- 5. The duplicates step 2 and step 3 have just created: https://a.com/ and
-- https://a.com were two rows and are now one value twice. The survivors are
-- byte-identical, so the only thing left to choose between them is created_at,
-- and MIN(id) keeps the earliest registration, which is the truer record. That
-- is the opposite end from migration 000030, where the rows differed and the
-- newest was the one in use.
--
-- The derived table is not decoration: MySQL refuses a subquery naming the table
-- being deleted from unless it is wrapped in one, and the same statement is then
-- legal on all four engines.
DELETE FROM web_origins
 WHERE id NOT IN (SELECT id FROM (SELECT MIN(id) AS id FROM web_origins GROUP BY origin, client_id) AS keep);

-- 6. The invariant the table has never expressed. Origin leads because that is
-- the only order the CORS lookup can use: WebOriginExists asks about an origin
-- with no client in hand, since a browser's preflight carries no client
-- identity. client_id follows because it is a label rather than a boundary, so
-- two clients may each list the same origin while one client lists it once.
CREATE UNIQUE INDEX `idx_web_origins_origin_client` ON `web_origins`(`origin`, `client_id`);
