-- See the sqlite migration of the same name: this table backed the server-side
-- session store that the chunked cookie store replaced, and nothing has used it
-- since. The index goes with the table.
DROP TABLE IF EXISTS `http_sessions`;
