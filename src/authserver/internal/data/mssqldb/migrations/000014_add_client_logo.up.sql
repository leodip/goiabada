-- Add client logos table
CREATE TABLE client_logos (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    created_at DATETIME2 NULL,
    updated_at DATETIME2 NULL,
    client_id BIGINT NOT NULL UNIQUE,
    logo VARBINARY(MAX) NOT NULL,
    content_type VARCHAR(64) NOT NULL,
    CONSTRAINT fk_client_logos_client_id
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
