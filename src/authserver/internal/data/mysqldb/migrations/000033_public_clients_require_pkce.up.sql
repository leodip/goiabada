-- A public client always requires PKCE (#245). See the sqlite migration of the
-- same number for why the column is migrated at all when the model rule already
-- answers `required`, and why the predicate is is_public rather than
-- pkce_required = false.
--
-- is_public is tinyint(1) here, so the literal is 1.
UPDATE clients SET pkce_required = 1 WHERE is_public = 1;
