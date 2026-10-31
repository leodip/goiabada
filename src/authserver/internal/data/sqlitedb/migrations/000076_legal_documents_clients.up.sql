-- Which apps a legal document applies to (#622, "Applies to"): all apps, the default, or the apps
-- an administrator selects. applies_to_all_apps says which; legal_documents_clients lists the
-- selected apps. A document set to selected apps with no app left in its list applies to nobody: it
-- never falls back to all apps, so deleting its last app cannot widen it to every user.
--
-- The six questions (reference/migrations.md 6): (1) all four engines. (2) No string column, so no
-- collation is pinned on a column. (3) The lookups compare ids. (4) A document lists an app once:
-- the pair is unique, and a list save that overlaps another meets the key as the 409 every list
-- save answers. (5) Every existing document keeps applying to all apps, which is what it did before
-- this migration: the new column defaults to true. (6) Each schema.golden gains the column and the
-- table.
--
-- Both foreign keys cascade, so deleting a document or a client removes its links; the document
-- stays on its other apps. The unique index leads with legal_document_id and serves the document's
-- list; the client's own index serves a client's documents and the cascade from clients.
ALTER TABLE legal_documents ADD COLUMN applies_to_all_apps numeric NOT NULL DEFAULT 1;
CREATE TABLE legal_documents_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NULL,
    legal_document_id INTEGER NOT NULL,
    client_id INTEGER NOT NULL,
    FOREIGN KEY (legal_document_id) REFERENCES legal_documents(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_legal_documents_clients_document_client ON legal_documents_clients(legal_document_id, client_id);
CREATE INDEX idx_legal_documents_clients_client_id ON legal_documents_clients(client_id);
