-- parity: sqlite only, matching the up migration.
--
-- Restores the shape golang-migrate's own SQLite driver builds: both columns nullable, no
-- primary key, and version_unique carrying the uniqueness on its own. The content rules the
-- up migration follows do not apply here, because the shape being restored is the one they
-- reject.
--
-- version_unique is recreated for the same reason the up migration recreates it: DROP TABLE
-- takes the index with it, and leaving it to the next ensureVersionTable would make the
-- table's shape depend on when the process restarts.
CREATE TABLE schema_migrations_old (version uint64, dirty bool);
INSERT INTO schema_migrations_old (version, dirty) SELECT version, dirty FROM schema_migrations;
DROP TABLE schema_migrations;
ALTER TABLE schema_migrations_old RENAME TO schema_migrations;
CREATE UNIQUE INDEX IF NOT EXISTS version_unique ON schema_migrations (version);
