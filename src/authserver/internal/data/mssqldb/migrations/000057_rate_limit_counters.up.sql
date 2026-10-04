-- The shared counts of the credential-guessing rate limits (#394). See the sqlite migration of the
-- same number for why, what a row is, and the six questions.
--
-- key_hash is pinned to the case-sensitive collation per column, as every string column is: the
-- database's own default is whatever an operator pre-created it with (#283).
CREATE TABLE [rate_limit_counters] (
    [key_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [window_start] DATETIME2(6) NOT NULL,
    [hits] INT NOT NULL,
    [expires_at] DATETIME2(6) NOT NULL,
    PRIMARY KEY ([key_hash], [window_start])
);
CREATE INDEX [idx_rate_limit_counters_expires_at] ON [rate_limit_counters]([expires_at]);
