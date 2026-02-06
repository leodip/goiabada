-- Add client logos table
CREATE TABLE client_logos (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP NULL,
    updated_at TIMESTAMP NULL,
    client_id BIGINT NOT NULL UNIQUE,
    logo BYTEA NOT NULL,
    content_type VARCHAR(64) NOT NULL,
    CONSTRAINT fk_client_logos_client_id
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
