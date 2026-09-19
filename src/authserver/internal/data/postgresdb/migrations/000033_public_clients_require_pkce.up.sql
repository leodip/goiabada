-- A public client always requires PKCE (#245). See the sqlite migration of the
-- same number for why the column is migrated at all when the model rule already
-- answers `required`, and why the predicate is is_public rather than
-- pkce_required = false.
--
-- is_public is a genuine `boolean` here, unlike the other three engines, so the
-- literal is true. Writing 1 would be a type error rather than a silent no-op,
-- but the pair is spelled out because the reverse mistake, `= true` on an
-- integer column, matches nothing and reports success.
UPDATE clients SET pkce_required = true WHERE is_public = true;
