-- A user's recovery codes (#257 decisions 2 and 3). See the sqlite migration of the same number for
-- why, for the six questions and for what the index serves.
--
-- The hash is pinned to the case-sensitive collation per column, as every string column is: the
-- database's own default is whatever an operator pre-created it with, and an unpinned column would
-- compare a hash case-insensitively there (#283). The one cascade starts from users, which reaches
-- this table by no other path.
CREATE TABLE [user_recovery_codes] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [user_id] BIGINT NOT NULL,
    [code_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [created_at] DATETIME2(6) NOT NULL,
    [used_at] DATETIME2(6) NULL,
    CONSTRAINT [fk_user_recovery_codes_user] FOREIGN KEY ([user_id])
        REFERENCES [users] ([id]) ON DELETE CASCADE
);
CREATE UNIQUE INDEX [idx_user_recovery_codes_user_code_hash] ON [user_recovery_codes]([user_id], [code_hash]);
