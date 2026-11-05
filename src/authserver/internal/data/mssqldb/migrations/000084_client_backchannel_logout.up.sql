-- A client's back-channel logout settings (#784 decision 14). See the sqlite migration of the same
-- number for what the columns hold and why nothing is backfilled.
--
-- NVARCHAR(2048) with the collation spelled out, as redirect_uris.uri is: the width is a redirect
-- URI's, the most the admin API and dynamic registration take, and
-- Latin1_General_100_CS_AS_KS_WS_SC_UTF8 is the case-, accent- and width-sensitive collation every
-- string column here carries since 000040.
--
-- The default constraints are NAMED for the reason 000031 gives: SQL Server refuses to drop a column
-- while a default constraint depends on it, so the down migration drops each constraint by name
-- first.
ALTER TABLE [clients] ADD [backchannel_logout_uri] NVARCHAR(2048) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_clients_backchannel_logout_uri] DEFAULT '';
ALTER TABLE [clients] ADD [backchannel_logout_session_required] BIT NOT NULL
    CONSTRAINT [df_clients_backchannel_logout_session_required] DEFAULT 0;
