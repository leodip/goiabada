CREATE TABLE [dbo].[http_sessions] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] datetime2(6),
    [updated_at] datetime2(6),
    [data] NVARCHAR(MAX),
    [expires_on] datetime2(6)
);
CREATE NONCLUSTERED INDEX [idx_httpsess_expires] ON [dbo].[http_sessions] ([expires_on]);
