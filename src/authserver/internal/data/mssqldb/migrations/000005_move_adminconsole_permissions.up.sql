-- Move built-in permissions from adminconsole resource to authserver resource
-- This migration:
-- 1. Moves 'manage' and 'manage-account' permissions from adminconsole to authserver
-- 2. Deletes the adminconsole resource only if no other permissions remain

-- Move the built-in permissions to authserver resource
UPDATE [dbo].[permissions]
SET resource_id = (SELECT id FROM [dbo].[resources] WHERE resource_identifier = 'authserver')
WHERE resource_id = (SELECT id FROM [dbo].[resources] WHERE resource_identifier = 'adminconsole')
  AND permission_identifier IN ('manage', 'manage-account');

-- Delete adminconsole resource only if it has no remaining permissions
DELETE FROM [dbo].[resources]
WHERE resource_identifier = 'adminconsole'
  AND NOT EXISTS (
    SELECT 1 FROM [dbo].[permissions] WHERE resource_id = [dbo].[resources].id
  );
