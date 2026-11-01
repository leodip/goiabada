-- Which user accepted which published version of a must-accept legal document, and when (#622).
-- See the sqlite migration of the same number for why, for the six questions and for what each
-- index serves.
--
-- One cascade, from users; the version's foreign key has none, so SQL Server sees a single cascade
-- path to this table.
CREATE TABLE [legal_document_acceptances] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [accepted_at] DATETIME2(6) NOT NULL,
    [user_id] BIGINT NOT NULL,
    [legal_document_version_id] BIGINT NOT NULL,
    CONSTRAINT [fk_legal_document_acceptances_user] FOREIGN KEY ([user_id])
        REFERENCES [users] ([id]) ON DELETE CASCADE,
    CONSTRAINT [fk_legal_document_acceptances_version] FOREIGN KEY ([legal_document_version_id])
        REFERENCES [legal_document_versions] ([id])
);
CREATE UNIQUE INDEX [idx_legal_document_acceptances_user_version] ON [legal_document_acceptances]([user_id], [legal_document_version_id]);
CREATE INDEX [idx_legal_document_acceptances_version_id] ON [legal_document_acceptances]([legal_document_version_id]);
