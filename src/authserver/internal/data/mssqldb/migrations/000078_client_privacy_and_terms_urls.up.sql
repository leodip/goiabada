-- A client's own privacy policy URL and terms of service URL (#622 decision 12). See the sqlite
-- migration of the same number for what the columns hold and why nothing is backfilled.
--
-- NVARCHAR(256) with the collation spelled out, as website_url is: the width is the URL they are
-- validated like, and Latin1_General_100_CS_AS_KS_WS_SC_UTF8 is the case-, accent- and
-- width-sensitive collation every string column here carries since 000040.
--
-- The default constraints are NAMED for the reason 000031 gives: SQL Server refuses to drop a column
-- while a default constraint depends on it, so the down migration drops each constraint by name
-- first.
ALTER TABLE [clients] ADD [privacy_policy_url] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_clients_privacy_policy_url] DEFAULT '';
ALTER TABLE [clients] ADD [terms_of_service_url] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_clients_terms_of_service_url] DEFAULT '';
