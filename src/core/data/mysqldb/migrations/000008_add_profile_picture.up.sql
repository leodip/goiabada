-- Add user profile pictures table
CREATE TABLE user_profile_pictures (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    created_at DATETIME(6) NULL,
    updated_at DATETIME(6) NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    picture LONGBLOB NOT NULL,
    content_type VARCHAR(64) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_user_profile_pictures_user_id (user_id),
    CONSTRAINT fk_user_profile_pictures_user_id
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
