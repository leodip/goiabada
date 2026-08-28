-- Every string column on this engine moves to Latin1_General_100_CS_AS_KS_WS_SC_UTF8, the case-,
-- accent-, width- and kanatype-SENSITIVE collation, so `=` and every UNIQUE index over a
-- string mean here what they already mean on SQLite and PostgreSQL (#283).
--
-- Why it is a conformance fix and not a preference. RFC 6749 section 1.9 says "Unless
-- otherwise noted, all the protocol parameter names and values are case sensitive", and
-- section 2.2 notes no exception for client_id; section 3.3 says the same of scope, whose
-- two halves are Goiabada's resource and permission identifiers; OpenID Connect Core
-- section 2 says "The sub value is a case-sensitive string". Under
-- Latin1_General_100_CI_AI_SC_UTF8, the collation NewMsSQLDatabase has pinned since SQL
-- Server support was added, a token request naming client_id=myapp resolves the client
-- registered as MyApp, which violates all three.
--
-- WHY THE KS_WS VARIANT AND NOT Latin1_General_100_CS_AS_SC_UTF8, the one #283 itself
-- names. Measured: the plain CS_AS form is still width-insensitive and
-- kanatype-insensitive, so a token request naming client_id in fullwidth characters would
-- go on resolving the client registered in ASCII. Only the KS_WS variant closes that, and
-- it sorts exactly as the current collation does and exactly as PostgreSQL does, so no
-- admin list reorders.
--
-- WHAT NO COLLATION CAN CLOSE, and where it is closed instead. SQL Server pads for `=`
-- under every collation including BIN2, so 'myapp' = 'myapp ' stays true here; and both
-- this collation and the old one compare NFC and NFD spellings of an accented character
-- equal. Neither is reachable through a lookup any more, because the data layer's five
-- identifier lookups now compare the row they got back against the value they were asked
-- for with Go's ==. A future query writing its own `=` needs the same guard.
--
-- The direction is the safe one. Going from a folding collation to a non-folding one only
-- ever RELAXES uniqueness, so no existing row can fail this conversion. The down migration
-- is the direction that can fail, and it says so.
--
-- The database default is NOT touched, and cannot be. Measured: ALTER DATABASE ... COLLATE
-- blocks until it times out the moment a second session is attached, which is exactly what
-- a running application and its connection pool are. NewMsSQLDatabase creates at the new
-- collation instead, and it creates IF NOT EXISTS, so a database an operator pre-created
-- keeps theirs. THE CONSEQUENCE, WHICH OUTLIVES THIS FILE: every string column a future
-- SQL Server migration adds must spell COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8
-- explicitly, or it lands at whatever that database's default is. A data test migrates the
-- whole chain into a deliberately hostile database and asserts all 92, so a migration that
-- forgets fails on the day it is written.
--
-- All 92 string columns, not only the ones holding an identity column. That is what makes
-- the rule mechanical: nobody has to decide whether the next column added is an identity
-- column. 23 indexes and 6 default constraints have to come off first, because ALTER
-- COLUMN under either fails Msg 5074 then Msg 4922.

-- 1. The six default constraints. Three were added without a name, so SQL Server generated
--    one, and a generated name DIFFERS PER DATABASE: a literal would work on exactly one
--    installation. They are read from the catalog and dropped through EXEC, which is what
--    000038 had to do for the fourth. They come back NAMED at the end, following the
--    convention 000024, 000026, 000029 and 000038 set, so a later migration can drop them
--    without repeating this lookup.

DECLARE @df1 sysname = (
    SELECT dc.[name] FROM sys.default_constraints dc
      JOIN sys.columns c ON c.[object_id] = dc.[parent_object_id] AND c.[column_id] = dc.[parent_column_id]
     WHERE dc.[parent_object_id] = OBJECT_ID('dbo.audit_logs') AND c.[name] = 'details');
EXEC('ALTER TABLE [audit_logs] DROP CONSTRAINT [' + @df1 + ']');

DECLARE @df2 sysname = (
    SELECT dc.[name] FROM sys.default_constraints dc
      JOIN sys.columns c ON c.[object_id] = dc.[parent_object_id] AND c.[column_id] = dc.[parent_column_id]
     WHERE dc.[parent_object_id] = OBJECT_ID('dbo.clients') AND c.[name] = 'display_name');
EXEC('ALTER TABLE [clients] DROP CONSTRAINT [' + @df2 + ']');

DECLARE @df3 sysname = (
    SELECT dc.[name] FROM sys.default_constraints dc
      JOIN sys.columns c ON c.[object_id] = dc.[parent_object_id] AND c.[column_id] = dc.[parent_column_id]
     WHERE dc.[parent_object_id] = OBJECT_ID('dbo.clients') AND c.[name] = 'website_url');
EXEC('ALTER TABLE [clients] DROP CONSTRAINT [' + @df3 + ']');

ALTER TABLE [clients] DROP CONSTRAINT [df_clients_include_open_id_connect_claims_in_id_token];
ALTER TABLE [pre_registrations] DROP CONSTRAINT [df_pre_registrations_verification_code_hash];
ALTER TABLE [users] DROP CONSTRAINT [df_users_forgot_password_code_hash];

-- 2. The 23 indexes over a string column. Recreated at the end with the same uniqueness
--    and the same key order; the catalog was read for both rather than the schema
--    snapshot, which is documentation and has drifted before.
DROP INDEX [idx_audit_logs_audit_event] ON [audit_logs];
DROP INDEX [idx_browser_sessions_owner_hash] ON [browser_sessions];
DROP INDEX [idx_client_identifier] ON [clients];
DROP INDEX [idx_code_hash] ON [codes];
DROP INDEX [idx_codes_session_identifier] ON [codes];
DROP INDEX [idx_group_identifier] ON [groups];
DROP INDEX [idx_key_pairs_state] ON [key_pairs];
DROP INDEX [idx_state] ON [key_pairs];
DROP INDEX [idx_permission_identifier_resource] ON [permissions];
DROP INDEX [idx_pre_reg_email] ON [pre_registrations];
DROP INDEX [idx_pre_reg_verification_code_hash] ON [pre_registrations];
DROP INDEX [idx_refresh_token_jti] ON [refresh_tokens];
DROP INDEX [idx_refresh_tokens_first_refresh_token_jti] ON [refresh_tokens];
DROP INDEX [idx_resource_identifier] ON [resources];
DROP INDEX [idx_session_identifier] ON [user_sessions];
DROP INDEX [idx_email] ON [users];
DROP INDEX [idx_family_name] ON [users];
DROP INDEX [idx_given_name] ON [users];
DROP INDEX [idx_middle_name] ON [users];
DROP INDEX [idx_subject] ON [users];
DROP INDEX [idx_username] ON [users];
DROP INDEX [idx_users_forgot_password_code_hash] ON [users];
DROP INDEX [idx_web_origins_origin_client] ON [web_origins];

-- 3. The 92 columns. EVERY ONE RESTATES ITS NULLABILITY, and that is not decoration:
--    ALTER TABLE ... ALTER COLUMN c <type> with neither NULL nor NOT NULL makes the column
--    NULLABLE whatever it was before, so writing these without the keyword would quietly
--    drop NOT NULL from 59 of the 92 while fixing their collation. That is the trap 000038
--    was written around, at 5 columns instead of 92.
ALTER TABLE [audit_logs] ALTER COLUMN [audit_event] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [audit_logs] ALTER COLUMN [details] NVARCHAR(MAX) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [browser_sessions] ALTER COLUMN [owner] NVARCHAR(20) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [browser_sessions] ALTER COLUMN [session_id_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [browser_sessions] ALTER COLUMN [data] NVARCHAR(MAX) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [client_logos] ALTER COLUMN [content_type] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [client_identifier] NVARCHAR(40) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [description] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [clients] ALTER COLUMN [include_open_id_connect_claims_in_access_token] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [default_acr_level] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [include_open_id_connect_claims_in_id_token] NVARCHAR(10) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [website_url] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [display_name] NVARCHAR(100) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [code_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [code_challenge] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [codes] ALTER COLUMN [code_challenge_method] NVARCHAR(10) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [codes] ALTER COLUMN [scope] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [state] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [nonce] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [redirect_uri] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [ip_address] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [user_agent] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [response_mode] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [session_identifier] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [acr_level] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [auth_methods] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [group_attributes] ALTER COLUMN [key] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [group_attributes] ALTER COLUMN [value] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [groups] ALTER COLUMN [group_identifier] NVARCHAR(40) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [groups] ALTER COLUMN [description] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [key_pairs] ALTER COLUMN [state] NVARCHAR(191) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [key_pairs] ALTER COLUMN [key_identifier] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [key_pairs] ALTER COLUMN [type] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [key_pairs] ALTER COLUMN [algorithm] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [permissions] ALTER COLUMN [permission_identifier] NVARCHAR(40) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [permissions] ALTER COLUMN [description] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [pre_registrations] ALTER COLUMN [email] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [pre_registrations] ALTER COLUMN [password_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [pre_registrations] ALTER COLUMN [verification_code_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [redirect_uris] ALTER COLUMN [uri] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [refresh_token_jti] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [previous_refresh_token_jti] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [first_refresh_token_jti] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [session_identifier] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [refresh_token_type] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [scope] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [resources] ALTER COLUMN [resource_identifier] NVARCHAR(40) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [resources] ALTER COLUMN [description] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [settings] ALTER COLUMN [app_name] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [settings] ALTER COLUMN [issuer] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [settings] ALTER COLUMN [ui_theme] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [settings] ALTER COLUMN [smtp_host] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [settings] ALTER COLUMN [smtp_username] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [settings] ALTER COLUMN [smtp_from_name] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [settings] ALTER COLUMN [smtp_from_email] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [settings] ALTER COLUMN [smtp_encryption] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [user_attributes] ALTER COLUMN [key] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [user_attributes] ALTER COLUMN [value] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [user_consents] ALTER COLUMN [scope] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [user_profile_pictures] ALTER COLUMN [content_type] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [session_identifier] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [auth_methods] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [acr_level] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [ip_address] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [device_name] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [device_type] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [device_os] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [users] ALTER COLUMN [subject] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [users] ALTER COLUMN [username] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [users] ALTER COLUMN [given_name] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [middle_name] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [family_name] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [nickname] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [website] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [gender] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [email] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [zone_info_country_name] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [zone_info] NVARCHAR(128) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [locale] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [phone_number] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [phone_number_country_uniqueid] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [phone_number_country_callingcode] NVARCHAR(16) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_line1] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_line2] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_locality] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_region] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_postal_code] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_country] NVARCHAR(32) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [password_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [users] ALTER COLUMN [otp_secret] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [forgot_password_code_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
ALTER TABLE [web_origins] ALTER COLUMN [origin] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

-- 4. The indexes back.
CREATE INDEX [idx_audit_logs_audit_event] ON [audit_logs]([audit_event]);
CREATE UNIQUE INDEX [idx_browser_sessions_owner_hash] ON [browser_sessions]([owner], [session_id_hash]);
CREATE UNIQUE INDEX [idx_client_identifier] ON [clients]([client_identifier]);
CREATE UNIQUE INDEX [idx_code_hash] ON [codes]([code_hash]);
CREATE INDEX [idx_codes_session_identifier] ON [codes]([session_identifier]);
CREATE UNIQUE INDEX [idx_group_identifier] ON [groups]([group_identifier]);
CREATE UNIQUE INDEX [idx_key_pairs_state] ON [key_pairs]([state]);
CREATE INDEX [idx_state] ON [key_pairs]([state]);
CREATE UNIQUE INDEX [idx_permission_identifier_resource] ON [permissions]([permission_identifier], [resource_id]);
CREATE INDEX [idx_pre_reg_email] ON [pre_registrations]([email]);
CREATE UNIQUE INDEX [idx_pre_reg_verification_code_hash] ON [pre_registrations]([verification_code_hash]);
CREATE UNIQUE INDEX [idx_refresh_token_jti] ON [refresh_tokens]([refresh_token_jti]);
CREATE INDEX [idx_refresh_tokens_first_refresh_token_jti] ON [refresh_tokens]([first_refresh_token_jti]);
CREATE UNIQUE INDEX [idx_resource_identifier] ON [resources]([resource_identifier]);
CREATE UNIQUE INDEX [idx_session_identifier] ON [user_sessions]([session_identifier]);
CREATE UNIQUE INDEX [idx_email] ON [users]([email]);
CREATE INDEX [idx_family_name] ON [users]([family_name]);
CREATE INDEX [idx_given_name] ON [users]([given_name]);
CREATE INDEX [idx_middle_name] ON [users]([middle_name]);
CREATE UNIQUE INDEX [idx_subject] ON [users]([subject]);
CREATE INDEX [idx_username] ON [users]([username]);
CREATE INDEX [idx_users_forgot_password_code_hash] ON [users]([forgot_password_code_hash]);
CREATE UNIQUE INDEX [idx_web_origins_origin_client] ON [web_origins]([origin], [client_id]);

-- 5. The defaults back, the three formerly auto-named ones now named.
ALTER TABLE [audit_logs] ADD CONSTRAINT [df_audit_logs_details] DEFAULT '{}' FOR [details];
ALTER TABLE [clients] ADD CONSTRAINT [df_clients_display_name] DEFAULT '' FOR [display_name];
ALTER TABLE [clients] ADD CONSTRAINT [df_clients_website_url] DEFAULT '' FOR [website_url];
ALTER TABLE [clients] ADD CONSTRAINT [df_clients_include_open_id_connect_claims_in_id_token] DEFAULT 'default' FOR [include_open_id_connect_claims_in_id_token];
ALTER TABLE [pre_registrations] ADD CONSTRAINT [df_pre_registrations_verification_code_hash] DEFAULT '' FOR [verification_code_hash];
ALTER TABLE [users] ADD CONSTRAINT [df_users_forgot_password_code_hash] DEFAULT '' FOR [forgot_password_code_hash];
