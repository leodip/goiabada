-- Web origins become the exact string a browser sends in an Origin header, and
-- the table starts saying that a client may list a given origin once (#250). See
-- the sqlite migration of the same number for why the rows need repairing, why
-- the order of the six steps is load-bearing, why the set repaired here is
-- exactly the set urlutil.CanonicalOrigin accepts, and why the delete lists what
-- is definitely wrong instead of whitelisting host characters.
--
-- What differs on this engine:
--   LENGTH() counts BYTES here. Every length test below uses CHAR_LENGTH(),
--   because a host with a multi-byte character would otherwise measure longer
--   than it is and a dot count taken from LENGTH() would still be right only by
--   luck.
--   Backslash is an escape character inside a string literal, so the backslash
--   test is written '\\'. Written '\' it would swallow the closing quote.
--   REGEXP replaces sqlite's GLOB and its rtrim-with-a-character-set trick: the
--   dotted quad and the "last label is a number" test are each one expression
--   here, which is why this file has no dig_tail/hex_tail columns.
UPDATE `web_origins` SET `origin` = TRIM(`origin`);
UPDATE `web_origins` SET `origin` = LOWER(`origin`);

-- Everything from the first '/', '?' or '#' after the authority, at the scheme's
-- known prefix length. The 1000000 sentinel is what makes LEAST() usable:
-- INSTR() reports 0 for absent, which would win against a genuine position, and
-- LEAST() itself returns NULL if handed one.
UPDATE `web_origins`
   SET `origin` = SUBSTRING(`origin`, 1, 7 + LEAST(
         COALESCE(NULLIF(INSTR(SUBSTRING(`origin`, 8), '/'), 0), 1000000),
         COALESCE(NULLIF(INSTR(SUBSTRING(`origin`, 8), '?'), 0), 1000000),
         COALESCE(NULLIF(INSTR(SUBSTRING(`origin`, 8), '#'), 0), 1000000)) - 1)
 WHERE `origin` LIKE 'http://%'
   AND (INSTR(SUBSTRING(`origin`, 8), '/') > 0
     OR INSTR(SUBSTRING(`origin`, 8), '?') > 0
     OR INSTR(SUBSTRING(`origin`, 8), '#') > 0);

UPDATE `web_origins`
   SET `origin` = SUBSTRING(`origin`, 1, 8 + LEAST(
         COALESCE(NULLIF(INSTR(SUBSTRING(`origin`, 9), '/'), 0), 1000000),
         COALESCE(NULLIF(INSTR(SUBSTRING(`origin`, 9), '?'), 0), 1000000),
         COALESCE(NULLIF(INSTR(SUBSTRING(`origin`, 9), '#'), 0), 1000000)) - 1)
 WHERE `origin` LIKE 'https://%'
   AND (INSTR(SUBSTRING(`origin`, 9), '/') > 0
     OR INSTR(SUBSTRING(`origin`, 9), '?') > 0
     OR INSTR(SUBSTRING(`origin`, 9), '#') > 0);

UPDATE `web_origins` SET `origin` = SUBSTRING(`origin`, 1, CHAR_LENGTH(`origin`) - 3)
 WHERE `origin` LIKE 'http://%:80';
UPDATE `web_origins` SET `origin` = SUBSTRING(`origin`, 1, CHAR_LENGTH(`origin`) - 4)
 WHERE `origin` LIKE 'https://%:443';

-- Over-long first. `origin` is varchar(256) here, so this is inert on this
-- engine; it is carried by all four files so they stay readable side by side, and
-- it is what removes sqlite's over-long rows, where the column is TEXT (#250
-- decision 14b).
DELETE FROM `web_origins` WHERE CHAR_LENGTH(`origin`) > 256;

-- Then every row that is still not exactly a canonical origin.
DELETE FROM `web_origins` WHERE `id` IN (
  SELECT `id` FROM (
    SELECT `id`, `authority`, `colon_at`,
           CASE WHEN `colon_at` > 0 THEN SUBSTRING(`authority`, 1, `colon_at` - 1)
                ELSE `authority` END AS `host`,
           CASE WHEN `colon_at` > 0 THEN SUBSTRING(`authority`, `colon_at` + 1)
                ELSE '' END AS `port`
      FROM (
        SELECT `id`, `authority`, INSTR(`authority`, ':') AS `colon_at`
          FROM (
            SELECT `id`,
                   CASE WHEN `origin` LIKE 'https://%' THEN SUBSTRING(`origin`, 9)
                        WHEN `origin` LIKE 'http://%'  THEN SUBSTRING(`origin`, 8)
                   END AS `authority`
              FROM `web_origins`
          ) AS a
      ) AS b
  ) AS c
  WHERE `authority` IS NULL
     OR `authority` = ''
     OR `authority` REGEXP '[^ -~]'
     OR INSTR(`authority`, ' ') > 0
     OR INSTR(`authority`, '@') > 0
     OR INSTR(`authority`, '[') > 0
     OR INSTR(`authority`, ']') > 0
     OR INSTR(`authority`, '%') > 0
     OR INSTR(`authority`, '\\') > 0
     OR INSTR(`authority`, '^') > 0
     OR INSTR(`authority`, '|') > 0
     OR INSTR(`authority`, '<') > 0
     OR INSTR(`authority`, '>') > 0
     OR INSTR(`authority`, '#') > 0
     OR INSTR(`authority`, '/') > 0
     OR INSTR(`authority`, '?') > 0
     OR CHAR_LENGTH(`authority`) - CHAR_LENGTH(REPLACE(`authority`, ':', '')) > 1
     OR (`colon_at` > 0 AND (`port` = ''
                          OR CHAR_LENGTH(`port`) > 5
                          OR `port` REGEXP '[^0-9]'
                          OR (CHAR_LENGTH(`port`) > 1 AND SUBSTRING(`port`, 1, 1) = '0')
                          OR (CHAR_LENGTH(`port`) = 5 AND `port` > '65535')))
     OR `host` = ''
     OR SUBSTRING(`host`, 1, 1) = '.'
     OR INSTR(`host`, '..') > 0
     -- A host that ends in an IPv4 number is kept only when it already is a
     -- strict dotted quad. The trailing dot is folded into both expressions as
     -- an optional '[.]?' rather than stripped first, since a browser drops it
     -- when the host parses as IPv4. Longest alternatives lead: MySQL's regex is
     -- leftmost-first, so '[0-9]' placed first would match the '2' of '255' and
     -- then fail on the rest.
     OR ((`host` REGEXP '(^|[.])[0-9]+[.]?$' OR `host` REGEXP '(^|[.])0x[0-9a-f]*[.]?$')
         AND `host` NOT REGEXP '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])([.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}$')
);

-- The duplicates the canonicalization has just created. MIN(id) keeps the
-- earliest registration, since the survivors are byte-identical and created_at
-- is all that distinguishes them. The derived table exists for this engine in
-- particular: MySQL refuses a subquery naming the table being deleted from
-- ("You can't specify target table 'web_origins' for update in FROM clause")
-- unless it is wrapped in one.
DELETE FROM `web_origins`
 WHERE `id` NOT IN (SELECT `id` FROM (SELECT MIN(`id`) AS `id` FROM `web_origins` GROUP BY `origin`, `client_id`) AS keep);

CREATE UNIQUE INDEX `idx_web_origins_origin_client` ON `web_origins`(`origin`, `client_id`);
