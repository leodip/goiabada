-- Deletes the authserver resource's userinfo permission and every user, group and client grant of
-- it (#449). See the sqlite migration of the same number for why no user loses anything by it.
--
-- The grants are deleted explicitly, before the permission, as on every engine, so the four agree
-- without relying on the link tables' ON DELETE CASCADE. The runner opens no transaction on this
-- engine; the statements are re-runnable in order, so a failure part way is completed by clearing
-- the dirty version and running the file again.
DELETE FROM `users_permissions`
WHERE `permission_id` IN (SELECT `p`.`id` FROM `permissions` `p` JOIN `resources` `r` ON `r`.`id` = `p`.`resource_id`
                          WHERE `r`.`resource_identifier` = 'authserver' AND `p`.`permission_identifier` = 'userinfo');

DELETE FROM `groups_permissions`
WHERE `permission_id` IN (SELECT `p`.`id` FROM `permissions` `p` JOIN `resources` `r` ON `r`.`id` = `p`.`resource_id`
                          WHERE `r`.`resource_identifier` = 'authserver' AND `p`.`permission_identifier` = 'userinfo');

DELETE FROM `clients_permissions`
WHERE `permission_id` IN (SELECT `p`.`id` FROM `permissions` `p` JOIN `resources` `r` ON `r`.`id` = `p`.`resource_id`
                          WHERE `r`.`resource_identifier` = 'authserver' AND `p`.`permission_identifier` = 'userinfo');

DELETE FROM `permissions`
WHERE `permission_identifier` = 'userinfo'
AND `resource_id` = (SELECT `id` FROM `resources` WHERE `resource_identifier` = 'authserver');
