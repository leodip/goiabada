-- Per-user OTP configuration generation (#242). See the sqlite migration of the same number for what
-- the columns mean, why both clauses of the seed are load-bearing, and why -1 is the seeded value.
--
-- The default constraints are NAMED deliberately, for the reason 000024 and 000029 give: SQL Server
-- refuses to drop a column while a default constraint depends on it, so the down migration has to
-- drop the constraint by name first.
ALTER TABLE [users] ADD [otp_config_generation] BIGINT NOT NULL
    CONSTRAINT [df_users_otp_config_generation] DEFAULT 0;
ALTER TABLE [user_sessions] ADD [otp_config_generation] BIGINT NOT NULL
    CONSTRAINT [df_user_sessions_otp_config_generation] DEFAULT 0;

-- The seed runs inside EXEC, which no other engine needs. SQL Server compiles an entire batch before
-- executing any of it, so a statement naming a column the same batch has just added fails at compile
-- time with "Invalid column name", before the ALTER above has run. EXEC defers name resolution to a
-- batch of its own. The usual separator would be GO, but that is a client-tool directive rather than
-- T-SQL and golang-migrate sends each migration file to the driver as one statement, so EXEC is the
-- separator available here. 000029 does exactly this and carries the same reasoning.
--
-- The boolean literal is 1 here rather than true: sql server declares both otp_enabled and
-- level2_auth_config_has_changed BIT, and = true is a syntax error on it.
EXEC('UPDATE [user_sessions] SET [otp_config_generation] = -1
 WHERE [level2_auth_config_has_changed] = 1
    OR [user_id] IN (SELECT [id] FROM [users] WHERE [otp_enabled] = 1)');

-- 000001 declares level2_auth_config_has_changed inline as BIT NOT NULL with no named default, so on
-- a database migrated forward from there this guard finds nothing and the drop proceeds. It exists
-- for the other arrival: the down migration below has to give the restored column a default, since
-- existing rows need a value, and without this guard the second up of a down-then-up round trip
-- would fail on the constraint it created. IF OBJECT_ID(...) IS NOT NULL is the idiom 000018 and
-- 000023 already use.
IF OBJECT_ID('df_user_sessions_level2_auth_config_has_changed', 'D') IS NOT NULL
    ALTER TABLE [user_sessions] DROP CONSTRAINT [df_user_sessions_level2_auth_config_has_changed];

ALTER TABLE [user_sessions] DROP COLUMN [level2_auth_config_has_changed];
