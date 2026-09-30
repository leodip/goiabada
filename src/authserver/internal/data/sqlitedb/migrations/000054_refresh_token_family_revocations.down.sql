-- Reverses migration 000054 (#132, #259, #437). DROP TABLE takes the primary key with it.
--
-- Every record is lost. A family revoked before the drop still has its revoked rows, so its
-- replay is still detected and its live members were revoked when it was recorded; what goes is
-- the refusal of a child that a rotation in flight was about to insert into it.
DROP TABLE refresh_token_family_revocations;
