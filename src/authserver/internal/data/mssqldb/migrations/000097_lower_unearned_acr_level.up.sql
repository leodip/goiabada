-- Lower to urn:goiabada:level1 every stored sign-in at urn:goiabada:level2_mandatory whose methods
-- name neither otp nor recovery_code (#199). See the sqlite migration of the same number for why
-- every such row is lowered and why to level1.
--
-- A method is named when the space-separated list holds exactly that name: the padded list and
-- name match whole names only. A binary collation makes the match exact, as on SQLite and
-- PostgreSQL, so case and ignorable characters count; CHARINDEX() pads neither side.
--
-- No EXEC wrapper, on 000033's reasoning: this names only columns that already exist, so a plain
-- statement resolves at batch compile time.
UPDATE [codes] SET [acr_level] = N'urn:goiabada:level1'
WHERE [acr_level] = N'urn:goiabada:level2_mandatory'
  AND CHARINDEX(N' otp ', (N' ' + [auth_methods] + N' ') COLLATE Latin1_General_100_BIN2) = 0
  AND CHARINDEX(N' recovery_code ', (N' ' + [auth_methods] + N' ') COLLATE Latin1_General_100_BIN2) = 0;
