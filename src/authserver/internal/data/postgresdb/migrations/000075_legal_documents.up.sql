-- Legal documents (#622 decisions 1 to 5). See the sqlite migration of the same number for why and
-- for the six questions. PostgreSQL compares strings byte-wise, so no column needs a collation pin;
-- the Markdown columns are TEXT, as audit_logs.details is.
CREATE TABLE legal_documents (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP(6),
    updated_at TIMESTAMP(6),
    short_name VARCHAR(64) NOT NULL,
    kind VARCHAR(20) NOT NULL,
    draft_title VARCHAR(200),
    draft_markdown TEXT,
    retired_at TIMESTAMP(6)
);
CREATE UNIQUE INDEX idx_legal_documents_short_name ON legal_documents (short_name);
CREATE TABLE legal_document_versions (
    id BIGSERIAL PRIMARY KEY,
    published_at TIMESTAMP(6) NOT NULL,
    legal_document_id BIGINT NOT NULL,
    version_number INTEGER NOT NULL,
    title VARCHAR(200) NOT NULL,
    markdown TEXT NOT NULL,
    CONSTRAINT fk_legal_document_versions_document FOREIGN KEY (legal_document_id) REFERENCES legal_documents (id)
);
CREATE UNIQUE INDEX idx_legal_document_versions_document_version ON legal_document_versions (legal_document_id, version_number);
