-- Add client logos table
CREATE TABLE client_logos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NULL,
    updated_at DATETIME NULL,
    client_id INTEGER NOT NULL UNIQUE,
    logo BLOB NOT NULL,
    content_type TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
