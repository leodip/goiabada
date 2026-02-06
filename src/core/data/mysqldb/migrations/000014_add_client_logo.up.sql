-- Add client logos table
CREATE TABLE client_logos (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    created_at DATETIME(6) NULL,
    updated_at DATETIME(6) NULL,
    client_id BIGINT UNSIGNED NOT NULL,
    logo LONGBLOB NOT NULL,
    content_type VARCHAR(64) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_client_logos_client_id (client_id),
    CONSTRAINT fk_client_logos_client_id
        FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
