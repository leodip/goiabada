-- Add user profile pictures table
CREATE TABLE user_profile_pictures (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP NULL,
    updated_at TIMESTAMP NULL,
    user_id BIGINT NOT NULL UNIQUE,
    picture BYTEA NOT NULL,
    content_type VARCHAR(64) NOT NULL,
    CONSTRAINT fk_user_profile_pictures_user_id
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
