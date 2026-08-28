-- Back to Latin1_General_100_CI_AI_SC_UTF8, which is where SQL Server stood before
-- #283 and which NewMsSQLDatabase pinned from the commit that added SQL Server support.
--
-- THIS DIRECTION IS ALLOWED TO FAIL, and on a deployment that has used the case-sensitive
-- schema it usually will. Latin1_General_100_CS_AS_KS_WS_SC_UTF8 permits `MyApp` and
-- `myapp` to coexist under idx_client_identifier; the CI_AI collation does not, so
-- CREATE UNIQUE INDEX is refused with Msg 1505 naming the first offending value. That
-- leaves schema_migrations DIRTY, which blocks every later run until an operator clears it
-- by hand, and the only way through is to resolve the duplicate rows first. Nothing here
-- can recover automatically: which of two rows the operator wants is not in the database.
--
-- What it also cannot recover: a collation an operator pre-created the database with. The
-- up migration converted all 92 columns to the target explicitly and the original
-- per-column collation is recorded nowhere. The old collation is therefore NAMED OUTRIGHT
-- rather than written DATABASE_DEFAULT. DATABASE_DEFAULT would restore an operator's own
-- choice, but on a database Goiabada created AFTER #283 it would leave every column
-- sitting at the new target after a rollback, so the version table would say something
-- untrue and down-then-up would stop being a round trip.
--
-- The nullability keyword is restated on every column here for the same reason the up
-- migration gives: omitting it makes the column nullable.
--
-- ATOMIC, and that is what makes the allowed failure survivable. golang-migrate's SQL Server
-- driver submits this file as ONE batch through a single ExecContext and opens no transaction
-- of its own, so without the pair below every statement autocommits as it runs. The refusal
-- above fires at step 4, by which point the 6 defaults and 23 indexes of steps 1 and 2 are
-- already gone for good and the 92 columns of step 3 have already moved: the operator is left
-- with a schema holding no UNIQUE index on client_identifier, email, subject, code_hash or
-- refresh_token_jti, and RETRYING after resolving the duplicate fails at the first DROP INDEX
-- with Msg 3701, because that index no longer exists. Decision 7 allows this direction to
-- fail; it does not allow it to leave a schema nobody can rebuild.
--
-- SET XACT_ABORT ON is required and not belt-and-braces. Msg 1505 is severity 16, which
-- terminates the statement and NOT the batch, so a bare BEGIN TRANSACTION would carry on to
-- the next CREATE INDEX and reach the COMMIT, committing exactly the half-dismantled schema
-- this is written to prevent. With it, the failure aborts the batch and rolls the whole file
-- back, so the operator finds every index, every default and the collation as they were,
-- resolves the duplicate, clears the dirty version by hand and runs it again.

SET XACT_ABORT ON;
BEGIN TRANSACTION;

-- 1. The defaults. The three the up migration NAMED go back UNNAMED, so a rollback lands
--    on exactly the shape 000008, 000013 and 000016 left: an auto-generated name.

ALTER TABLE [audit_logs] DROP CONSTRAINT [df_audit_logs_details];
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_display_name];
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_website_url];
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_include_open_id_connect_claims_in_id_token];
ALTER TABLE [pre_registrations] DROP CONSTRAINT [df_pre_registrations_verification_code_hash];
ALTER TABLE [users] DROP CONSTRAINT [df_users_forgot_password_code_hash];

-- 2. The 23 indexes over a string column.
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

-- 3. The 92 columns, back to the folding collation.
ALTER TABLE [audit_logs] ALTER COLUMN [audit_event] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [audit_logs] ALTER COLUMN [details] NVARCHAR(MAX) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [browser_sessions] ALTER COLUMN [owner] NVARCHAR(20) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [browser_sessions] ALTER COLUMN [session_id_hash] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [browser_sessions] ALTER COLUMN [data] NVARCHAR(MAX) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [client_logos] ALTER COLUMN [content_type] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [client_identifier] NVARCHAR(40) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [description] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [clients] ALTER COLUMN [include_open_id_connect_claims_in_access_token] NVARCHAR(16) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [default_acr_level] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [include_open_id_connect_claims_in_id_token] NVARCHAR(10) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [website_url] NVARCHAR(256) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [clients] ALTER COLUMN [display_name] NVARCHAR(100) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [code_hash] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [code_challenge] NVARCHAR(256) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [codes] ALTER COLUMN [code_challenge_method] NVARCHAR(10) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [codes] ALTER COLUMN [scope] NVARCHAR(512) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [state] NVARCHAR(512) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [nonce] NVARCHAR(512) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [redirect_uri] NVARCHAR(256) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [ip_address] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [user_agent] NVARCHAR(512) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [response_mode] NVARCHAR(16) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [session_identifier] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [acr_level] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [auth_methods] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [group_attributes] ALTER COLUMN [key] NVARCHAR(32) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [group_attributes] ALTER COLUMN [value] NVARCHAR(256) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [groups] ALTER COLUMN [group_identifier] NVARCHAR(40) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [groups] ALTER COLUMN [description] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [key_pairs] ALTER COLUMN [state] NVARCHAR(191) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [key_pairs] ALTER COLUMN [key_identifier] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [key_pairs] ALTER COLUMN [type] NVARCHAR(16) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [key_pairs] ALTER COLUMN [algorithm] NVARCHAR(16) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [permissions] ALTER COLUMN [permission_identifier] NVARCHAR(40) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [permissions] ALTER COLUMN [description] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [pre_registrations] ALTER COLUMN [email] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [pre_registrations] ALTER COLUMN [password_hash] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [pre_registrations] ALTER COLUMN [verification_code_hash] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [redirect_uris] ALTER COLUMN [uri] NVARCHAR(256) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [refresh_token_jti] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [previous_refresh_token_jti] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [first_refresh_token_jti] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [session_identifier] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [refresh_token_type] NVARCHAR(16) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [refresh_tokens] ALTER COLUMN [scope] NVARCHAR(512) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [resources] ALTER COLUMN [resource_identifier] NVARCHAR(40) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [resources] ALTER COLUMN [description] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [settings] ALTER COLUMN [app_name] NVARCHAR(32) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [settings] ALTER COLUMN [issuer] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [settings] ALTER COLUMN [ui_theme] NVARCHAR(32) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [settings] ALTER COLUMN [smtp_host] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [settings] ALTER COLUMN [smtp_username] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [settings] ALTER COLUMN [smtp_from_name] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [settings] ALTER COLUMN [smtp_from_email] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [settings] ALTER COLUMN [smtp_encryption] NVARCHAR(16) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [user_attributes] ALTER COLUMN [key] NVARCHAR(32) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [user_attributes] ALTER COLUMN [value] NVARCHAR(256) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [user_consents] ALTER COLUMN [scope] NVARCHAR(512) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [user_profile_pictures] ALTER COLUMN [content_type] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [session_identifier] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [auth_methods] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [acr_level] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [ip_address] NVARCHAR(512) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [device_name] NVARCHAR(256) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [device_type] NVARCHAR(32) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [user_sessions] ALTER COLUMN [device_os] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [users] ALTER COLUMN [subject] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [users] ALTER COLUMN [username] NVARCHAR(32) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [users] ALTER COLUMN [given_name] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [middle_name] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [family_name] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [nickname] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [website] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [gender] NVARCHAR(16) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [email] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [zone_info_country_name] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [zone_info] NVARCHAR(128) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [locale] NVARCHAR(32) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [phone_number] NVARCHAR(32) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [phone_number_country_uniqueid] NVARCHAR(16) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [phone_number_country_callingcode] NVARCHAR(16) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_line1] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_line2] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_locality] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_region] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_postal_code] NVARCHAR(32) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [address_country] NVARCHAR(32) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [password_hash] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [users] ALTER COLUMN [otp_secret] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NULL;
ALTER TABLE [users] ALTER COLUMN [forgot_password_code_hash] NVARCHAR(64) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;
ALTER TABLE [web_origins] ALTER COLUMN [origin] NVARCHAR(256) COLLATE Latin1_General_100_CI_AI_SC_UTF8 NOT NULL;

-- 4. The indexes back. This is where Msg 1505 fires if a case-variant pair exists.
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

-- 5. The defaults back, the three the up migration named restored as unnamed.
ALTER TABLE [audit_logs] ADD DEFAULT '{}' FOR [details];
ALTER TABLE [clients] ADD DEFAULT '' FOR [display_name];
ALTER TABLE [clients] ADD DEFAULT '' FOR [website_url];
ALTER TABLE [clients] ADD CONSTRAINT [df_clients_include_open_id_connect_claims_in_id_token] DEFAULT 'default' FOR [include_open_id_connect_claims_in_id_token];
ALTER TABLE [pre_registrations] ADD CONSTRAINT [df_pre_registrations_verification_code_hash] DEFAULT '' FOR [verification_code_hash];
ALTER TABLE [users] ADD CONSTRAINT [df_users_forgot_password_code_hash] DEFAULT '' FOR [forgot_password_code_hash];

COMMIT TRANSACTION;
SET XACT_ABORT OFF;
