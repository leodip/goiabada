-- Email template edits (#818 decision 7). See the sqlite migration of the same number for why and
-- for the six questions. PostgreSQL compares strings byte-wise, so no column needs a collation pin;
-- the body is TEXT, as the legal documents' Markdown is.
CREATE TABLE email_templates (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP(6),
    updated_at TIMESTAMP(6),
    email_template VARCHAR(64) NOT NULL,
    language VARCHAR(32) NOT NULL,
    subject VARCHAR(200),
    button_label VARCHAR(60),
    body TEXT
);
CREATE UNIQUE INDEX idx_email_templates_email_template_language ON email_templates (email_template, language);
