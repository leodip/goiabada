-- The raw User-Agent header on the session row (#281). See the sqlite migration of the same number
-- for what the column holds, why it and ip_address are the "same device" key from here, and why
-- pre-upgrade rows reading '' is accepted rather than backfilled.
--
-- NVARCHAR rather than VARCHAR and the collation spelled out, as every string column on this table
-- already is: the sweep compares two headers for equality, and Latin1_General_100_CS_AS_KS_WS_SC_UTF8
-- is what makes that comparison case-, accent- and width-sensitive here as it is on the other three
-- engines (#283). 512 UTF-16 units holds any value useragent.Bound produces, since a 512-byte string
-- is at most 512 units.
--
-- The default constraint is NAMED for the reason 000031 gives: SQL Server refuses to drop a column
-- while a default constraint depends on it, so the down migration drops the constraint by name first.
ALTER TABLE [user_sessions] ADD [user_agent] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_user_sessions_user_agent] DEFAULT '';
