-- A self-registered client has both legacy flows off on itself (#542 review). See the sqlite
-- migration of the same number for why, and why only a NULL becomes off.
UPDATE [clients] SET [implicit_grant_enabled] = 0
 WHERE [created_via_dcr] = 1 AND [implicit_grant_enabled] IS NULL;

UPDATE [clients] SET [resource_owner_password_credentials_enabled] = 0
 WHERE [created_via_dcr] = 1 AND [resource_owner_password_credentials_enabled] IS NULL;
