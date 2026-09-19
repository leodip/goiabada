-- Add user profile pictures table
CREATE TABLE user_profile_pictures (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    created_at DATETIME2 NULL,
    updated_at DATETIME2 NULL,
    user_id BIGINT NOT NULL UNIQUE,
    picture VARBINARY(MAX) NOT NULL,
    content_type VARCHAR(64) NOT NULL,
    CONSTRAINT fk_user_profile_pictures_user_id
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
