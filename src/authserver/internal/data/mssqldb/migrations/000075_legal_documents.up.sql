-- Legal documents (#622 decisions 1 to 5). See the sqlite migration of the same number for why and
-- for the six questions.
--
-- Every string column is pinned to the case-sensitive collation per column, as every string column
-- is: the database's own default is whatever an operator pre-created it with (#283). The Markdown
-- columns are NVARCHAR(MAX), as audit_logs.details is.
CREATE TABLE [legal_documents] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] DATETIME2(6) NULL,
    [updated_at] DATETIME2(6) NULL,
    [short_name] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [kind] NVARCHAR(20) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [draft_title] NVARCHAR(200) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL,
    [draft_markdown] NVARCHAR(MAX) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL,
    [retired_at] DATETIME2(6) NULL
);
CREATE UNIQUE INDEX [idx_legal_documents_short_name] ON [legal_documents]([short_name]);
CREATE TABLE [legal_document_versions] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [published_at] DATETIME2(6) NOT NULL,
    [legal_document_id] BIGINT NOT NULL,
    [version_number] INT NOT NULL,
    [title] NVARCHAR(200) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [markdown] NVARCHAR(MAX) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    CONSTRAINT [fk_legal_document_versions_document] FOREIGN KEY ([legal_document_id])
        REFERENCES [legal_documents] ([id])
);
CREATE UNIQUE INDEX [idx_legal_document_versions_document_version] ON [legal_document_versions]([legal_document_id], [version_number]);
