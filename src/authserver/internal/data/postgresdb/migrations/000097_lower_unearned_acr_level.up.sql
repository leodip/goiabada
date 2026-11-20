-- Lower to urn:goiabada:level1 every stored sign-in at urn:goiabada:level2_mandatory whose methods
-- name neither otp nor recovery_code (#199). See the sqlite migration of the same number for why
-- every such row is lowered and why to level1.
--
-- A method is named when the space-separated list holds exactly that name: the padded list and
-- name match whole names only, and strpos() compares exactly, case included.
UPDATE codes SET acr_level = 'urn:goiabada:level1'
WHERE acr_level = 'urn:goiabada:level2_mandatory'
  AND strpos(' ' || auth_methods || ' ', ' otp ') = 0
  AND strpos(' ' || auth_methods || ' ', ' recovery_code ') = 0;
