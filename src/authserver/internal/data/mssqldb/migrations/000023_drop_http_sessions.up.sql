-- See the sqlite migration of the same name. Dropping the table drops its index.
IF OBJECT_ID('[dbo].[http_sessions]', 'U') IS NOT NULL
    DROP TABLE [dbo].[http_sessions];
