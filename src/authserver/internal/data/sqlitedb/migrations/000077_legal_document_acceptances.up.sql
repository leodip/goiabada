-- Which user accepted which published version of a must-accept legal document, and when (#622,
-- "What an acceptance records"). The acceptance step writes a row for each document a user accepts;
-- a version names its document, so a newer version of the same document is a new row, which is how
-- a new version is asked again.
--
-- The six questions (reference/migrations.md 6): (1) all four engines. (2) No string column, so no
-- collation is pinned on a column. (3) The lookups compare ids. (4) A user accepts a version once:
-- the pair is unique, and two submissions of one step racing to record it meet the key. (5) No
-- existing row changes meaning, and nothing is backfilled: nobody has accepted anything before
-- this migration. (6) Each schema.golden gains the table.
--
-- Deleting the user removes their acceptances. The version's foreign key has no cascade: a version
-- is never deleted, and the engine refuses a delete that would take what a user accepted. The
-- unique index leads with user_id and serves a user's acceptances and the cascade from users; the
-- version's own index serves the foreign key's checks.
CREATE TABLE legal_document_acceptances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    accepted_at DATETIME NOT NULL,
    user_id INTEGER NOT NULL,
    legal_document_version_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (legal_document_version_id) REFERENCES legal_document_versions(id)
);
CREATE UNIQUE INDEX idx_legal_document_acceptances_user_version ON legal_document_acceptances(user_id, legal_document_version_id);
CREATE INDEX idx_legal_document_acceptances_version_id ON legal_document_acceptances(legal_document_version_id);
