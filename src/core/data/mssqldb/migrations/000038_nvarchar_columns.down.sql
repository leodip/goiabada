-- Back to VARCHAR, which is where SQL Server stood before #282.
--
-- This direction can lose characters: under an ASCII-lossy collation such as
-- SQL_Latin1_General_CP1_CI_AS, every stored character outside the code page is
-- replaced with '?' on the way down and is not recovered by re-applying the up
-- migration. Under the Latin1_General_100_CI_AI_SC_UTF8 collation NewMsSQLDatabase
-- pins, nothing is lost in either direction.
--
-- The nullability keyword is restated on every column here for the same reason the up
-- migration gives: omitting it makes the column nullable.

-- The named constraint has to go before the column can be altered, and it goes back
-- UNNAMED so the down lands on exactly the shape 000013 left: an auto-generated name.
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_include_open_id_connect_claims_in_id_token];

ALTER TABLE [clients] ALTER COLUMN [include_open_id_connect_claims_in_id_token] VARCHAR(10) NOT NULL;

ALTER TABLE [clients] ADD DEFAULT 'default' FOR [include_open_id_connect_claims_in_id_token];

ALTER TABLE [client_logos] ALTER COLUMN [content_type] VARCHAR(64) NOT NULL;
ALTER TABLE [user_profile_pictures] ALTER COLUMN [content_type] VARCHAR(64) NOT NULL;
ALTER TABLE [codes] ALTER COLUMN [code_challenge_method] VARCHAR(10) NULL;
ALTER TABLE [codes] ALTER COLUMN [code_challenge] VARCHAR(256) NULL;
