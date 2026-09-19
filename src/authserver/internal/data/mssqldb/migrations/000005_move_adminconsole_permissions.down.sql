-- Rollback: Move permissions back from authserver to adminconsole resource
-- This migration reverses the permission move

-- Recreate adminconsole resource if it doesn't exist
IF NOT EXISTS (SELECT 1 FROM [dbo].[resources] WHERE resource_identifier = 'adminconsole')
BEGIN
    INSERT INTO [dbo].[resources] (created_at, updated_at, resource_identifier, description)
    VALUES (GETDATE(), GETDATE(), 'adminconsole', 'Admin console');
END

-- Move the permissions back to adminconsole resource
UPDATE [dbo].[permissions]
SET resource_id = (SELECT id FROM [dbo].[resources] WHERE resource_identifier = 'adminconsole')
WHERE resource_id = (SELECT id FROM [dbo].[resources] WHERE resource_identifier = 'authserver')
  AND permission_identifier IN ('manage', 'manage-account');
