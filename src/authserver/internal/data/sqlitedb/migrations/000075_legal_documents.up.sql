-- Legal documents (#622 decisions 1 to 5): the privacy notices and terms of use an administrator
-- publishes, each a document with numbered versions. A document is drafted, then published: the
-- draft lives on the document's row and is edited as often as the administrator likes, and Publish
-- freezes it as the next row of legal_document_versions, which is never rewritten.
--
-- The six questions a migration answers: (1) all four engines. (2) short_name, kind and the titles
-- are pinned case-sensitive on MySQL and SQL Server, as every string column is; the two Markdown
-- columns are unbounded, as audit_logs.details is. (3) A document is found by its short name with =,
-- and the data layer rechecks the match in Go, as it does every identifier lookup. (4) short_name
-- is unique among documents, and a document has one version of each number; both are the engine's
-- to refuse, so two publishes racing for the same number cannot both win. (5) No existing row
-- changes meaning, and nothing is backfilled: there are no documents until an administrator writes
-- one. (6) Each schema.golden gains the two tables.
--
-- A version's foreign key has no cascade: a document with a published version is never deleted,
-- only retired (decision 2), and the engine refuses the delete that would take its versions.
CREATE TABLE legal_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    short_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    draft_title TEXT,
    draft_markdown TEXT,
    retired_at DATETIME
);
CREATE UNIQUE INDEX idx_legal_documents_short_name ON legal_documents (short_name);
CREATE TABLE legal_document_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    published_at DATETIME NOT NULL,
    legal_document_id INTEGER NOT NULL,
    version_number INTEGER NOT NULL,
    title TEXT NOT NULL,
    markdown TEXT NOT NULL,
    CONSTRAINT fk_legal_document_versions_document FOREIGN KEY (legal_document_id) REFERENCES legal_documents (id)
);
CREATE UNIQUE INDEX idx_legal_document_versions_document_version ON legal_document_versions (legal_document_id, version_number);
