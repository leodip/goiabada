-- Add user profile pictures table
CREATE TABLE user_profile_pictures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NULL,
    updated_at DATETIME NULL,
    user_id INTEGER NOT NULL UNIQUE,
    picture BLOB NOT NULL,
    content_type TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
