-- Which apps a legal document applies to (#622, "Applies to"). See the sqlite migration of the
-- same number for why, for the six questions and for what each index serves.
--
-- The two cascades start from two tables, legal_documents and clients, neither of which reaches the
-- other, so SQL Server sees no cycle and no second cascade path to this table.
ALTER TABLE [legal_documents] ADD [applies_to_all_apps] BIT NOT NULL
    CONSTRAINT [df_legal_documents_applies_to_all_apps] DEFAULT 1;
CREATE TABLE [legal_documents_clients] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] DATETIME2(6) NULL,
    [legal_document_id] BIGINT NOT NULL,
    [client_id] BIGINT NOT NULL,
    CONSTRAINT [fk_legal_documents_clients_document] FOREIGN KEY ([legal_document_id])
        REFERENCES [legal_documents] ([id]) ON DELETE CASCADE,
    CONSTRAINT [fk_legal_documents_clients_client] FOREIGN KEY ([client_id])
        REFERENCES [clients] ([id]) ON DELETE CASCADE
);
CREATE UNIQUE INDEX [idx_legal_documents_clients_document_client] ON [legal_documents_clients]([legal_document_id], [client_id]);
CREATE INDEX [idx_legal_documents_clients_client_id] ON [legal_documents_clients]([client_id]);
