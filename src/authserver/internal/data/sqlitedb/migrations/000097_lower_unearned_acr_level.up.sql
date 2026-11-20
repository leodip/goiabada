-- Migration 000097: lower to urn:goiabada:level1 every stored sign-in at
-- urn:goiabada:level2_mandatory whose methods name neither otp nor recovery_code (#199).
--
-- Releases before 1.7.0 could store a sign-in that way, through three bugs since fixed (#133, its
-- sibling for a user's own expired session, and #537): a level claiming a second factor the
-- sign-in did not perform. Every refresh copies the stored level into its tokens, so a grant from
-- such a sign-in went on claiming it. Nothing stored tells the three sources apart, and the level
-- is false for all of them, so every such row is lowered, whenever it was created. level1 is the
-- only level a password alone proves, and the lowest there is, which is also what is left for a
-- row recording no methods at all.
--
-- A method is named when the space-separated list holds exactly that name, case included, as the
-- ceremony reads a second-factor claim: padding the list and the name with a space each side
-- matches whole names only, so xotp, otpx and OTP name nothing and their rows are lowered. instr()
-- compares characters exactly, unlike LIKE, which folds ASCII case here and reads _ as a wildcard.
--
-- Only the level changes. The methods, the authentication time and every other column stay, and
-- rows at the two lower levels or naming a second factor are not touched. Nothing is revoked and
-- nobody is signed out: the grant's next refresh carries the lowered level.
UPDATE codes SET acr_level = 'urn:goiabada:level1'
WHERE acr_level = 'urn:goiabada:level2_mandatory'
  AND instr(' ' || auth_methods || ' ', ' otp ') = 0
  AND instr(' ' || auth_methods || ' ', ' recovery_code ') = 0;
