-- Rollback: Move permissions back from authserver to adminconsole resource
-- This migration reverses the permission move

-- Recreate adminconsole resource if it doesn't exist
INSERT IGNORE INTO resources (created_at, updated_at, resource_identifier, description)
SELECT NOW(), NOW(), 'adminconsole', 'Admin console'
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM resources WHERE resource_identifier = 'adminconsole');

-- Move the permissions back to adminconsole resource
UPDATE permissions
SET resource_id = (SELECT id FROM resources WHERE resource_identifier = 'adminconsole')
WHERE resource_id = (SELECT id FROM resources WHERE resource_identifier = 'authserver')
  AND permission_identifier IN ('manage', 'manage-account');
