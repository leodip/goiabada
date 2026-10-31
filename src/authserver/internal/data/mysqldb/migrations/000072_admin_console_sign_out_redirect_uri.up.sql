-- The admin console's base URL moves from its client's redirect URIs to its sign-out redirect URIs
-- (#147 decision 8). See the sqlite migration of the same number for which rows move and why.
--
-- The partner is compared as bytes: the column's collation folds a composed accent onto its
-- decomposed spelling, and a binary string is never padded. The delete joins rather than naming
-- redirect_uris in a subquery, which MySQL refuses for the table a statement deletes from.
INSERT INTO `post_logout_redirect_uris` (`created_at`, `uri`, `client_id`)
SELECT `bare`.`created_at`, `bare`.`uri`, `bare`.`client_id`
  FROM `redirect_uris` AS `bare`
 INNER JOIN `clients` ON `clients`.`id` = `bare`.`client_id`
 WHERE `clients`.`client_identifier` = 'admin-console-client'
   AND EXISTS (SELECT 1 FROM `redirect_uris` AS `callback`
                WHERE `callback`.`client_id` = `bare`.`client_id`
                  AND CAST(`callback`.`uri` AS BINARY) = CAST(CONCAT(`bare`.`uri`, '/auth/callback') AS BINARY));

DELETE `bare`
  FROM `redirect_uris` AS `bare`
 INNER JOIN `clients` ON `clients`.`id` = `bare`.`client_id`
 INNER JOIN `redirect_uris` AS `callback`
    ON `callback`.`client_id` = `bare`.`client_id`
   AND CAST(`callback`.`uri` AS BINARY) = CAST(CONCAT(`bare`.`uri`, '/auth/callback') AS BINARY)
 WHERE `clients`.`client_identifier` = 'admin-console-client';
