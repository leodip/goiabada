-- The browser session moves out of the cookie and into a row (#266). See the sqlite
-- migration of the same number for why the table is named browser_sessions rather than
-- http_sessions, why session_id_hash holds a digest rather than the identifier, what the
-- owner column keeps apart, and why the new permission is narrow.
--
-- No EXEC wrapper. SQL Server compiles a whole batch before executing any of it, which
-- is why migration 000029 needs one for an UPDATE naming a column the same batch adds.
-- Nothing below names a column that does not already exist: the CREATE INDEX statements
-- name a table created in this batch, which deferred name resolution handles, and the
-- INSERTs and the UPDATE touch only pre-existing tables.
CREATE TABLE [browser_sessions] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] DATETIME2(6) NULL,
    [updated_at] DATETIME2(6) NULL,
    [owner] NVARCHAR(20) NOT NULL,
    [session_id_hash] NVARCHAR(64) NOT NULL,
    [data] NVARCHAR(MAX) NULL,
    [last_accessed] DATETIME2(6) NOT NULL,
    [expires_at] DATETIME2(6) NOT NULL
);
CREATE UNIQUE INDEX [idx_browser_sessions_owner_hash] ON [browser_sessions]([owner], [session_id_hash]);
CREATE INDEX [idx_browser_sessions_expires_at] ON [browser_sessions]([expires_at]);

INSERT INTO [permissions] ([created_at], [updated_at], [permission_identifier], [description], [resource_id])
SELECT GETDATE(), GETDATE(), 'browser-sessions', 'Read and write admin console browser sessions', [id]
FROM [resources] WHERE [resource_identifier] = 'authserver'
AND NOT EXISTS (SELECT 1 FROM [permissions] WHERE [permission_identifier] = 'browser-sessions' AND [resource_id] = (SELECT [id] FROM [resources] WHERE [resource_identifier] = 'authserver'));

INSERT INTO [clients_permissions] ([created_at], [updated_at], [client_id], [permission_id])
SELECT GETDATE(), GETDATE(), c.[id], p.[id]
FROM [clients] c CROSS JOIN [permissions] p
WHERE c.[client_identifier] = 'admin-console-client'
AND p.[permission_identifier] = 'browser-sessions'
AND p.[resource_id] = (SELECT [id] FROM [resources] WHERE [resource_identifier] = 'authserver')
AND NOT EXISTS (SELECT 1 FROM [clients_permissions] cp WHERE cp.[client_id] = c.[id] AND cp.[permission_id] = p.[id]);

-- client_credentials_enabled is BIT here, so the literal is 1.
UPDATE [clients] SET [client_credentials_enabled] = 1 WHERE [client_identifier] = 'admin-console-client';
