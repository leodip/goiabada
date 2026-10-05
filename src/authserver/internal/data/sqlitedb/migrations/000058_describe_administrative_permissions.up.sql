-- Rewrites the descriptions of four administrative permissions on the authserver resource so they
-- state the boundary #402 draws: only authserver:manage creates, changes or reaches an
-- administrator, and the granular scopes manage everyone else (#402 decision 3). The console shows
-- these descriptions where an operator picks a permission to grant, which is where the boundary is
-- decided. admin-read, manage-account and browser-sessions keep theirs, and no identifier changes:
-- the identifiers are the wire contract.
--
-- A row is rewritten only where it still carries the wording the seed or 000012 gave it, so a
-- description an operator has edited is theirs and is kept. The column is compared exactly here,
-- and the pinned case- and accent-sensitive collations make it exact on MySQL and SQL Server too.
-- The seed writes the same wording on a fresh installation, which reaches this migration with no
-- authserver resource and so rewrites nothing.
--
-- Data only: no schema change. Each statement is re-runnable, and this engine's runner wraps the
-- file in one transaction regardless.

UPDATE permissions SET description = 'Full administration, including administrators and administrative permissions', updated_at = datetime('now')
WHERE permission_identifier = 'manage' AND description = 'Manage the authorization server via the admin console'
AND resource_id = (SELECT id FROM resources WHERE resource_identifier = 'authserver');

UPDATE permissions SET description = 'Manage users and groups that are not administrators, and their non-administrative permissions', updated_at = datetime('now')
WHERE permission_identifier = 'manage-users' AND description = 'Manage users, groups, and permissions'
AND resource_id = (SELECT id FROM resources WHERE resource_identifier = 'authserver');

UPDATE permissions SET description = 'Manage OAuth2 clients that are not administrators', updated_at = datetime('now')
WHERE permission_identifier = 'manage-clients' AND description = 'Manage OAuth2 clients'
AND resource_id = (SELECT id FROM resources WHERE resource_identifier = 'authserver');

UPDATE permissions SET description = 'Manage system settings, except email and audit logging, and signing keys', updated_at = datetime('now')
WHERE permission_identifier = 'manage-settings' AND description = 'Manage system settings and signing keys'
AND resource_id = (SELECT id FROM resources WHERE resource_identifier = 'authserver');
