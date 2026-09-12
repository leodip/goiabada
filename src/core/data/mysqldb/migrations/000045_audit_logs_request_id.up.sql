-- audit_logs rows carry the request id of the request that raised the event (#328). See the
-- sqlite migration of the same number for what the column holds, why the client-chosen value
-- is safe to store at this width, and why the index lands here with no reader yet.
--
-- The collation is spelled because MySQL applies the table's otherwise, and #283 found three
-- tables carrying a folding collation that way. A request id is compared with = by the filter
-- the next stage adds, so folding here would answer the wrong question.
ALTER TABLE `audit_logs`
    ADD COLUMN `request_id` varchar(256) COLLATE utf8mb4_0900_as_cs NOT NULL DEFAULT '';

CREATE INDEX `idx_audit_logs_request_id` ON `audit_logs`(`request_id`);
