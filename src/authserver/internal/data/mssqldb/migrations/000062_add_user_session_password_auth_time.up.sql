-- A session records when its password was entered, apart from auth_time (#542 review). See the
-- sqlite migration of the same number for why every stored session is ended, and the mysql one for
-- why the column is added with a default that is dropped at once and the sessions deleted last: a
-- rolling upgrade's previous release goes on inserting sessions while this runs.
ALTER TABLE [user_sessions] ADD [password_auth_time] DATETIME2(6) NOT NULL
    CONSTRAINT [df_user_sessions_password_auth_time] DEFAULT '1970-01-01T00:00:00';
ALTER TABLE [user_sessions] DROP CONSTRAINT [df_user_sessions_password_auth_time];

DELETE FROM [user_sessions];
