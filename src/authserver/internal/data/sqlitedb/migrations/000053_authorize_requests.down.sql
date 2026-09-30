-- Reverses migration 000053 (#246, #437). DROP TABLE takes both indexes with it on every engine,
-- so they are not dropped separately.
--
-- Every parked request is lost. Each lives five minutes at most and is consumed within a
-- second in ordinary use, so a browser caught in the middle of one is sent back to the
-- application to start again, as it is when a request expires.
DROP TABLE authorize_requests;
