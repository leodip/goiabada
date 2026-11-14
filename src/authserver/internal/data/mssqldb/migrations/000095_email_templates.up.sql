-- Email template edits (#818 decision 7). See the sqlite migration of the same number for why and
-- for the six questions.
--
-- Every string column is pinned to the case-sensitive collation per column, as every string column
-- is: the database's own default is whatever an operator pre-created it with (#283). The subject and
-- the button label are as wide as their bounds, which count UTF-16 code units as NVARCHAR does; the
-- body is NVARCHAR(MAX), as the legal documents' Markdown is.
CREATE TABLE [email_templates] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] DATETIME2(6) NULL,
    [updated_at] DATETIME2(6) NULL,
    [email_template] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [language] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [subject] NVARCHAR(200) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL,
    [button_label] NVARCHAR(60) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL,
    [body] NVARCHAR(MAX) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL
);
CREATE UNIQUE INDEX [idx_email_templates_email_template_language] ON [email_templates]([email_template], [language]);
