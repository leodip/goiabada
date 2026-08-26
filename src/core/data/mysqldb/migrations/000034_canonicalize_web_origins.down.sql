-- Dropping the index is the whole of the rollback, and it is deliberately not an
-- inverse: a canonicalized value is one that already worked, the original text is
-- recorded nowhere, and the deleted rows never matched an Origin header (#250).
DROP INDEX `idx_web_origins_origin_client` ON `web_origins`;
