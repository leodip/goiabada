-- A client's brand (#812 decision 1). See the sqlite migration of the same number for why and for
-- the six questions. The foreign key is named, so the down can drop it before the column.
ALTER TABLE [clients] ADD [brand_id] BIGINT NULL
    CONSTRAINT [fk_clients_brand] FOREIGN KEY REFERENCES [brands] ([id]);
CREATE INDEX [idx_clients_brand_id] ON [clients]([brand_id]);
