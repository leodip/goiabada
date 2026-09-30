-- Reverses migration 000054 (#132, #259, #437). See the sqlite migration of the same number for
-- what is lost: every record, and with it the refusal of a child a rotation in flight was about to
-- insert into a revoked family.
DROP TABLE refresh_token_family_revocations;
