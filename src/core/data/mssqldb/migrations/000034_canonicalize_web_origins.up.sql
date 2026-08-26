-- Web origins become the exact string a browser sends in an Origin header, and
-- the table starts saying that a client may list a given origin once (#250). See
-- the sqlite migration of the same number for why the rows need repairing, why
-- the order of the six steps is load-bearing, why the set repaired here is
-- exactly the set urlutil.CanonicalOrigin accepts, and why the delete lists what
-- is definitely wrong instead of whitelisting host characters.
--
-- What differs on this engine:
--   CHARINDEX(needle, haystack) takes its arguments in the OPPOSITE order to
--   instr(). Written the other way round it compiles and reports 0 for
--   everything, which is a delete predicate that silently deletes nothing.
--   The default collation is case-insensitive and accent-sensitive, so LOWER() is
--   still needed for the stored value even though the LIKE tests would not notice
--   the difference, and the non-ASCII test needs an explicit binary collation to
--   compare by code unit.
--   There is no LEAST() before SQL Server 2022, so the smallest of the three
--   delimiter positions comes from a VALUES table.
--   LIKE character classes replace GLOB, and RIGHT()/REVERSE() replace SQLite's
--   rtrim-with-a-character-set trick for reading the last label.
--
-- No EXEC wrapper, unlike 000029: this migration adds no column, so nothing in
-- the batch names an identifier the same batch has just created.
UPDATE [web_origins] SET [origin] = LTRIM(RTRIM([origin]));
UPDATE [web_origins] SET [origin] = LOWER([origin]);

-- Everything from the first '/', '?' or '#' after the authority, at the scheme's
-- known prefix length. The 1000000 sentinel is what makes the MIN usable:
-- CHARINDEX reports 0 for absent, which would win against a genuine position.
UPDATE [web_origins]
   SET [origin] = SUBSTRING([origin], 1, 7 + (SELECT MIN(v) FROM (VALUES
         (COALESCE(NULLIF(CHARINDEX('/', SUBSTRING([origin], 8, LEN([origin]))), 0), 1000000)),
         (COALESCE(NULLIF(CHARINDEX('?', SUBSTRING([origin], 8, LEN([origin]))), 0), 1000000)),
         (COALESCE(NULLIF(CHARINDEX('#', SUBSTRING([origin], 8, LEN([origin]))), 0), 1000000))
       ) AS t(v)) - 1)
 WHERE [origin] LIKE 'http://%'
   AND (CHARINDEX('/', SUBSTRING([origin], 8, LEN([origin]))) > 0
     OR CHARINDEX('?', SUBSTRING([origin], 8, LEN([origin]))) > 0
     OR CHARINDEX('#', SUBSTRING([origin], 8, LEN([origin]))) > 0);

UPDATE [web_origins]
   SET [origin] = SUBSTRING([origin], 1, 8 + (SELECT MIN(v) FROM (VALUES
         (COALESCE(NULLIF(CHARINDEX('/', SUBSTRING([origin], 9, LEN([origin]))), 0), 1000000)),
         (COALESCE(NULLIF(CHARINDEX('?', SUBSTRING([origin], 9, LEN([origin]))), 0), 1000000)),
         (COALESCE(NULLIF(CHARINDEX('#', SUBSTRING([origin], 9, LEN([origin]))), 0), 1000000))
       ) AS t(v)) - 1)
 WHERE [origin] LIKE 'https://%'
   AND (CHARINDEX('/', SUBSTRING([origin], 9, LEN([origin]))) > 0
     OR CHARINDEX('?', SUBSTRING([origin], 9, LEN([origin]))) > 0
     OR CHARINDEX('#', SUBSTRING([origin], 9, LEN([origin]))) > 0);

-- The colon count is a correctness guard rather than an optimisation: exactly
-- two colons means the authority holds exactly one, and stripping a default port
-- off a two-port authority would turn a row the delete below removes into a live
-- origin it keeps. The sqlite file carries the full reasoning (#250). LEN is the
-- idiom the delete below already counts colons with, and it is safe here despite
-- ignoring trailing spaces: step 1 trimmed them and the LIKE anchors the last
-- character on a digit.
UPDATE [web_origins] SET [origin] = SUBSTRING([origin], 1, LEN([origin]) - 3)
 WHERE [origin] LIKE 'http://%:80'
   AND LEN([origin]) - LEN(REPLACE([origin], ':', '')) = 2;
UPDATE [web_origins] SET [origin] = SUBSTRING([origin], 1, LEN([origin]) - 4)
 WHERE [origin] LIKE 'https://%:443'
   AND LEN([origin]) - LEN(REPLACE([origin], ':', '')) = 2;

-- Over-long first. [origin] is NVARCHAR(256) here, so this is inert on this
-- engine; it is carried by all four files so they stay readable side by side, and
-- it is what removes sqlite's over-long rows, where the column is TEXT (#250
-- decision 14b).
DELETE FROM [web_origins] WHERE LEN([origin]) > 256;

-- Then every row that is still not exactly a canonical origin.
DELETE FROM [web_origins] WHERE [id] IN (
  SELECT [id] FROM (
    SELECT [id], [authority], [colon_at], [host], [port],
           -- A single trailing dot is a distinct host a browser serializes
           -- verbatim, so it is not part of the name when deciding whether the
           -- host ends in a number.
           CASE WHEN CHARINDEX('.', REVERSE([h2])) = 0 THEN [h2]
                ELSE RIGHT([h2], CHARINDEX('.', REVERSE([h2])) - 1) END AS [last_label]
      FROM (
        SELECT [id], [authority], [colon_at], [host], [port],
               CASE WHEN RIGHT([host], 1) = '.' THEN LEFT([host], LEN([host]) - 1)
                    ELSE [host] END AS [h2]
          FROM (
            SELECT [id], [authority], [colon_at],
                   CASE WHEN [colon_at] > 0 THEN SUBSTRING([authority], 1, [colon_at] - 1)
                        ELSE [authority] END AS [host],
                   CASE WHEN [colon_at] > 0 THEN SUBSTRING([authority], [colon_at] + 1, LEN([authority]))
                        ELSE '' END AS [port]
              FROM (
                SELECT [id], [authority], CHARINDEX(':', [authority]) AS [colon_at]
                  FROM (
                    SELECT [id],
                           CASE WHEN [origin] LIKE 'https://%' THEN SUBSTRING([origin], 9, LEN([origin]))
                                WHEN [origin] LIKE 'http://%'  THEN SUBSTRING([origin], 8, LEN([origin]))
                           END AS [authority]
                      FROM [web_origins]
                  ) AS a
              ) AS b
          ) AS c
      ) AS d
  ) AS e
  WHERE [authority] IS NULL
     OR [authority] = ''
     -- Latin1_General_BIN2 compares NVARCHAR by UTF-16 code unit, so the range
     -- means U+0020 to U+007E and nothing else. Under the default collation the
     -- same test would let accented characters through as their base letters.
     OR [authority] COLLATE Latin1_General_BIN2 LIKE N'%[^ -~]%'
     OR CHARINDEX(' ', [authority]) > 0
     OR CHARINDEX('@', [authority]) > 0
     OR CHARINDEX('[', [authority]) > 0
     OR CHARINDEX(']', [authority]) > 0
     OR CHARINDEX('%', [authority]) > 0
     OR CHARINDEX('\', [authority]) > 0
     OR CHARINDEX('^', [authority]) > 0
     OR CHARINDEX('|', [authority]) > 0
     OR CHARINDEX('<', [authority]) > 0
     OR CHARINDEX('>', [authority]) > 0
     OR CHARINDEX('#', [authority]) > 0
     OR CHARINDEX('/', [authority]) > 0
     OR CHARINDEX('?', [authority]) > 0
     OR LEN([authority]) - LEN(REPLACE([authority], ':', '')) > 1
     OR ([colon_at] > 0 AND ([port] = ''
                          OR LEN([port]) > 5
                          OR [port] LIKE '%[^0-9]%'
                          OR (LEN([port]) > 1 AND LEFT([port], 1) = '0')
                          OR (LEN([port]) = 5 AND [port] > '65535')))
     OR [host] = ''
     OR LEFT([host], 1) = '.'
     OR CHARINDEX('..', [host]) > 0
     -- A host that ends in an IPv4 number is kept only when it already is a
     -- strict dotted quad. Padding to '.' + host + '.' makes "some label exceeds
     -- 255" position-independent, so it is three patterns rather than nine.
     OR ((([last_label] <> '' AND [last_label] NOT LIKE '%[^0-9]%')
          OR ([last_label] LIKE '0x%'
              AND SUBSTRING([last_label], 3, LEN([last_label])) NOT LIKE '%[^0-9a-f]%'))
         AND NOT ([host] NOT LIKE '%[^0-9.]%'
              AND LEN([host]) - LEN(REPLACE([host], '.', '')) = 3
              AND LEFT([host], 1) <> '.'
              AND RIGHT([host], 1) <> '.'
              AND CHARINDEX('..', [host]) = 0
              AND [host] NOT LIKE '%[0-9][0-9][0-9][0-9]%'
              AND '.' + [host] + '.' NOT LIKE '%.0[0-9]%'
              AND '.' + [host] + '.' NOT LIKE '%.[3-9][0-9][0-9].%'
              AND '.' + [host] + '.' NOT LIKE '%.2[6-9][0-9].%'
              AND '.' + [host] + '.' NOT LIKE '%.25[6-9].%'))
);

-- The duplicates the canonicalization has just created. MIN(id) keeps the
-- earliest registration, since the survivors are byte-identical and created_at is
-- all that distinguishes them.
DELETE FROM [web_origins]
 WHERE [id] NOT IN (SELECT [id] FROM (SELECT MIN([id]) AS [id] FROM [web_origins] GROUP BY [origin], [client_id]) AS keep);

CREATE UNIQUE INDEX [idx_web_origins_origin_client] ON [web_origins] ([origin], [client_id]);
