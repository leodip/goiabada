-- audit_logs rows record the user they are about and the user who acted (#780 decisions 1 and 2), so
-- one person's events are found without reading every row's details.
--
-- user_id is the user the event is about, copied from the details' user_id when the event is
-- written. logged_in_user_id is the user whose access token made the request: the administrator on
-- the admin API, the user themselves on the account API, NULL on a browser sign-in, off a request
-- and on a client credentials token. Both are the users row's numeric id.
--
-- Nullable, and no foreign key: an audit row outlives the user it names, which is what audit rows
-- are for, and NULL is what every row written before this migration carries. Those rows are not
-- backfilled; they age out with retention.
--
-- Each column has an index of its own, the shape of every other audit_logs index. The user filter
-- matches either column (user_id = N OR logged_in_user_id = N), so every engine reads both indexes
-- and sorts what they find; one user's rows are few enough to sort cheaply. Building the indexes
-- reads every stored row, so on a large audit table this migration takes longer than usual.
ALTER TABLE audit_logs ADD COLUMN user_id INTEGER NULL;
ALTER TABLE audit_logs ADD COLUMN logged_in_user_id INTEGER NULL;

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_logged_in_user_id ON audit_logs(logged_in_user_id);
