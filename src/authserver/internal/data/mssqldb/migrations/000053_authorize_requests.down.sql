-- Reverses migration 000053 (#246, #437). See the sqlite migration of the same number for what
-- is lost: every parked request, each of which lives five minutes at most.
DROP TABLE [authorize_requests];
