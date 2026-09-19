-- parity: sqlite only. browser_sessions.data is declared `longtext` here, which is a MySQL
-- type name that reached a SQLite migration. On MySQL it is real and it is the right choice,
-- being that engine's largest string at 4 GiB; SQLite has no such type. It was copied across
-- with the rest of the table when 000035 created it on all four engines, and SQLite took it
-- without complaint, because SQLite accepts any type name at all and assigns affinity by
-- substring: "longtext" contains "TEXT", so the column has TEXT affinity and behaves exactly
-- as a column declared TEXT would. PostgreSQL and SQL Server spell their own and need no
-- file.
--
-- So no behaviour changes, and this is still not cosmetic. The declared type is what SQLite's
-- catalog reports and therefore what the golden file records, so the committed record of the
-- SQLite schema currently describes a column in another engine's vocabulary, standing beside
-- 90 that say TEXT. It is the exact class of drift #284 was opened to find, and the class
-- where the damage is done later: the next person to add a string column to a SQLite
-- migration copies a neighbouring line, and this is the neighbour that is wrong. Decision 6
-- puts it on this branch with a migration rather than on the allowlist or a follow-up.
--
-- SQLite cannot ALTER a column's type, so the table is rebuilt, in 000041's shape.
--
-- The safety argument is decision 9's, and it is about DROP TABLE rather than about the copy.
-- DROP TABLE fires an implicit DELETE that cascades into any table holding a foreign key onto
-- this one, and PRAGMA foreign_keys is a no-op inside the transaction golang-migrate wraps
-- this file in, so a naive rebuild silently empties the referencing table
-- (probe/sqlite_rebuild_fk.out, variants A through D). Nothing references browser_sessions on
-- any of the four engines: no REFERENCES browser_sessions appears in any migration chain. So
-- there is nothing to cascade into and no table to park first, which is why this is the plain
-- rebuild and not variant E.
--
-- Both indexes are recreated, because DROP TABLE takes them with it, spelled exactly as
-- 000035 spelled them. The per-engine golden assertion is what holds that claim rather than
-- the eye.
--
-- One consequence, weighed and accepted. DROP TABLE also removes the table's sqlite_sequence
-- row; the INSERT below re-establishes it at the highest id copied across, so an install
-- whose reaper had already deleted its newest rows resumes numbering below the high-water
-- mark AUTOINCREMENT otherwise guarantees, and an id can be issued twice over the life of the
-- database. id is a surrogate key. A browser session is found by (owner, session_id_hash),
-- BrowserSession.Id is never put in the cookie or in any token, and no table has a foreign
-- key onto it, so a repeat is unobservable. Preserving the mark would mean parking the value
-- in a temp table and restoring it around the rename, three statements guarding a number
-- nothing reads.
CREATE TABLE browser_sessions_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    owner TEXT NOT NULL,
    session_id_hash TEXT NOT NULL,
    data TEXT,
    last_accessed DATETIME NOT NULL,
    expires_at DATETIME NOT NULL
);
INSERT INTO browser_sessions_new (id, created_at, updated_at, owner, session_id_hash, data, last_accessed, expires_at)
SELECT id, created_at, updated_at, owner, session_id_hash, data, last_accessed, expires_at FROM browser_sessions;
DROP TABLE browser_sessions;
ALTER TABLE browser_sessions_new RENAME TO browser_sessions;
CREATE UNIQUE INDEX idx_browser_sessions_owner_hash ON browser_sessions(owner, session_id_hash);
CREATE INDEX idx_browser_sessions_expires_at ON browser_sessions(expires_at);
