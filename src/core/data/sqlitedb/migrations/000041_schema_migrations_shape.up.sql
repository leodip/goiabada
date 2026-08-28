-- parity: sqlite only. golang-migrate's MySQL, PostgreSQL and SQL Server drivers all build
-- schema_migrations as (version bigint not null primary key, dirty boolean not null); only
-- the SQLite driver builds (version uint64, dirty bool), nullable and keyless, with a
-- separate version_unique index. So this is a levelling-up of the one engine out of line,
-- and the other three need no file (#284 decision 7).
--
-- NewMigrator pre-creates the table at this shape, which settles a NEW install. This
-- settles an install created before that existed. The two have to agree, because the
-- four-engine parity check reads schema_migrations like any other table.
--
-- Not cosmetic, and the NOT NULL that carries the weight is dirty's. The driver's shape
-- stores a NULL in either column; golang-migrate's Version() scans both into Go values, and
-- when the scan fails it SWALLOWS the error and reports NilVersion, which is the value that
-- makes it run the whole chain from 000001 against a populated database. After the rebuild
-- dirty refuses a NULL outright. version cannot hold one either, but by a different
-- mechanism worth knowing before anyone "tidies" this: SQLite REPLACES a NULL in an INTEGER
-- PRIMARY KEY with a generated rowid, NOT NULL or not, so the column never rejects a NULL
-- and never stores one (probe/sqlite_version_table.out case 5).
--
-- INTEGER and not BIGINT: only INTEGER PRIMARY KEY is a rowid alias. Spelled BIGINT, SQLite
-- builds sqlite_autoindex_schema_migrations_1 to enforce the key, and ensureVersionTable's
-- unconditional CREATE UNIQUE INDEX IF NOT EXISTS version_unique then lands on top of it,
-- leaving two unique indexes on one column where the other three engines have one.
--
-- The rows are copied with no WHERE. A row the pinned shape refuses fails this migration
-- inside golang-migrate's transaction, which rolls back and leaves the operator a visible
-- error; filtering it out instead would drop the recorded version silently and leave
-- golang-migrate re-running the chain from 000001 against a populated database.
--
-- version_unique is recreated here rather than left to the next ensureVersionTable, so the
-- table has the same shape immediately after this migration as it does after a restart.
CREATE TABLE schema_migrations_new (
    version INTEGER NOT NULL PRIMARY KEY,
    dirty BOOLEAN NOT NULL
);
INSERT INTO schema_migrations_new (version, dirty) SELECT version, dirty FROM schema_migrations;
DROP TABLE schema_migrations;
ALTER TABLE schema_migrations_new RENAME TO schema_migrations;
CREATE UNIQUE INDEX IF NOT EXISTS version_unique ON schema_migrations (version);
