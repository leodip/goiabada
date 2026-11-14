-- Email template edits (#818 decision 7): an administrator's edit of one email in one language,
-- holding only what differs from the built-in text. Each of the subject, the button label and the
-- body is NULL for a field left as the built-in text, so that field follows later releases; a row
-- with none of them set is not kept, since a save whose text is the built-in one deletes it.
-- Nothing about whether an edit is valid is stored: that is judged whenever it is read (decision 8).
--
-- The six questions a migration answers: (1) all four engines. (2) email_template is the email's
-- fixed identifier, such as password_reset_link, and language one of the six built-in language
-- tags, both ASCII; the three fields are the administrator's text. Every string column is pinned
-- case-sensitive on MySQL and SQL Server, as every string column is; the subject and the button
-- label are as wide as their bounds, 200 and 60, and the body is unbounded, as the legal
-- documents' Markdown is, since its bound of 20,000 is past what an NVARCHAR(n) holds. (3) An edit
-- is found by its email and language with =, and the data layer rechecks the match in Go, as it
-- does every identifier lookup. (4) An email and a language have at most one row: the unique index
-- is the engine's to keep, and a save writes it as an insert that replaces the row already there,
-- so two saves at once leave the last one's. (5) No existing row changes meaning, and nothing is
-- backfilled: there are no edits until an administrator saves one. (6) Each schema.golden gains the
-- table.
--
-- The previous release never reads the table, so a replica of it still serving during a rolling
-- upgrade sends every email with the text it ships.
CREATE TABLE email_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    email_template TEXT NOT NULL,
    language TEXT NOT NULL,
    subject TEXT,
    button_label TEXT,
    body TEXT
);
CREATE UNIQUE INDEX idx_email_templates_email_template_language ON email_templates (email_template, language);
