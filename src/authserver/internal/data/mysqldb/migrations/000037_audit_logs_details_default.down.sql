-- Back to a TEXT column with no default, which is where MySQL stood before #282.
ALTER TABLE `audit_logs` MODIFY `details` TEXT NOT NULL;
