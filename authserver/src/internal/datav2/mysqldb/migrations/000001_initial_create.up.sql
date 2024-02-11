-- BEGIN

CREATE TABLE `clients` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `client_identifier` varchar(40) NOT NULL,
  `client_secret_encrypted` longblob,
  `description` varchar(128) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL,
  `consent_required` tinyint(1) NOT NULL,
  `is_public` tinyint(1) NOT NULL,
  `authorization_code_enabled` tinyint(1) NOT NULL,
  `client_credentials_enabled` tinyint(1) NOT NULL,
  `token_expiration_in_seconds` int NOT NULL,
  `refresh_token_offline_idle_timeout_in_seconds` int NOT NULL,
  `refresh_token_offline_max_lifetime_in_seconds` int NOT NULL,
  `include_open_id_connect_claims_in_access_token` varchar(16) NOT NULL,
  `default_acr_level` varchar(128) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_client_identifier` (`client_identifier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `resources` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `resource_identifier` varchar(40) NOT NULL,
  `description` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_resource_identifier` (`resource_identifier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `permissions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `permission_identifier` varchar(40) NOT NULL,
  `description` varchar(128) DEFAULT NULL,
  `resource_id` bigint unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_permission_identifier` (`permission_identifier`),
  KEY `fk_permissions_resource` (`resource_id`),
  CONSTRAINT `fk_permissions_resource` FOREIGN KEY (`resource_id`) REFERENCES `resources` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `clients_permissions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `client_id` bigint unsigned NOT NULL,  
  `permission_id` bigint unsigned NOT NULL,  
  PRIMARY KEY (`id`),
  KEY `fk_clients_permissions_client` (`client_id`),
  KEY `fk_clients_permissions_permission` (`permission_id`),
  CONSTRAINT `fk_clients_permissions_client` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`),
  CONSTRAINT `fk_clients_permissions_permission` FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `users` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `enabled` tinyint(1) NOT NULL,
  `subject` varchar(64) NOT NULL,
  `username` varchar(32) NOT NULL,
  `given_name` varchar(64) DEFAULT NULL,
  `middle_name` varchar(64) DEFAULT NULL,
  `family_name` varchar(64) DEFAULT NULL,
  `nickname` varchar(64) DEFAULT NULL,
  `website` varchar(128) DEFAULT NULL,
  `gender` varchar(16) DEFAULT NULL,
  `email` varchar(64) DEFAULT NULL,
  `email_verified` tinyint(1) NOT NULL,
  `email_verification_code_encrypted` longblob,
  `email_verification_code_issued_at` datetime(6) DEFAULT NULL,
  `zone_info_country_name` varchar(128) DEFAULT NULL,
  `zone_info` varchar(128) DEFAULT NULL,
  `locale` varchar(32) DEFAULT NULL,
  `birth_date` datetime(6) DEFAULT NULL,
  `phone_number` varchar(32) DEFAULT NULL,
  `phone_number_verified` tinyint(1) NOT NULL,
  `phone_number_verification_code_encrypted` longblob,
  `phone_number_verification_code_issued_at` datetime(6) DEFAULT NULL,
  `address_line1` varchar(64) DEFAULT NULL,
  `address_line2` varchar(64) DEFAULT NULL,
  `address_locality` varchar(64) DEFAULT NULL,
  `address_region` varchar(64) DEFAULT NULL,
  `address_postal_code` varchar(32) DEFAULT NULL,
  `address_country` varchar(32) DEFAULT NULL,
  `password_hash` varchar(64) NOT NULL,
  `otp_secret` varchar(64) DEFAULT NULL,
  `otp_enabled` tinyint(1) NOT NULL,
  `forgot_password_code_encrypted` longblob,
  `forgot_password_code_issued_at` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_subject` (`subject`),
  UNIQUE KEY `idx_email` (`email`),
  KEY `idx_username` (`username`),
  KEY `idx_given_name` (`given_name`),
  KEY `idx_middle_name` (`middle_name`),
  KEY `idx_family_name` (`family_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `codes` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `code_hash` varchar(64) NOT NULL,
  `client_id` bigint unsigned NOT NULL,
  `code_challenge` varchar(256) NOT NULL,
  `code_challenge_method` varchar(10) NOT NULL,
  `scope` varchar(512) NOT NULL,
  `state` varchar(512) NOT NULL,
  `nonce` varchar(512) NOT NULL,
  `redirect_uri` varchar(256) NOT NULL,
  `user_id` bigint unsigned NOT NULL,
  `ip_address` varchar(64) NOT NULL,
  `user_agent` varchar(512) NOT NULL,
  `response_mode` varchar(16) NOT NULL,
  `authenticated_at` datetime(6) NOT NULL,
  `session_identifier` varchar(64) NOT NULL,
  `acr_level` varchar(128) NOT NULL,
  `auth_methods` varchar(64) NOT NULL,
  `used` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_code_hash` (`code_hash`),
  KEY `fk_codes_client` (`client_id`),
  KEY `fk_codes_user` (`user_id`),
  CONSTRAINT `fk_codes_client` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`),
  CONSTRAINT `fk_codes_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `groups` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `group_identifier` varchar(40) NOT NULL,
  `description` varchar(128) DEFAULT NULL,
  `include_in_id_token` tinyint(1) NOT NULL,
  `include_in_access_token` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_group_identifier` (`group_identifier`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `group_attributes` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `key` varchar(32) NOT NULL,
  `value` varchar(256) NOT NULL,
  `include_in_id_token` tinyint(1) NOT NULL,
  `include_in_access_token` tinyint(1) NOT NULL,
  `group_id` bigint unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_groups_attributes` (`group_id`),
  CONSTRAINT `fk_groups_attributes` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `groups_permissions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `group_id` bigint unsigned NOT NULL,
  `permission_id` bigint unsigned NOT NULL,  
  PRIMARY KEY (`id`),
  KEY `fk_groups_permissions_group` (`group_id`),
  KEY `fk_groups_permissions_permission` (`permission_id`),
  CONSTRAINT `fk_groups_permissions_group` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`),
  CONSTRAINT `fk_groups_permissions_permission` FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `http_sessions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `data` longtext,  
  `expires_on` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_httpsess_expires` (`expires_on`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `key_pairs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `state` varchar(191) NOT NULL,
  `key_identifier` varchar(64) NOT NULL,
  `type` varchar(16) NOT NULL,
  `algorithm` varchar(16) NOT NULL,
  `private_key_pem` longblob,
  `public_key_pem` longblob,
  `public_key_asn1_der` longblob,
  `public_key_jwk` longblob,
  PRIMARY KEY (`id`),
  KEY `idx_state` (`state`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `pre_registrations` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `email` varchar(64) DEFAULT NULL,
  `password_hash` varchar(64) NOT NULL,
  `verification_code_encrypted` longblob,
  `verification_code_issued_at` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_pre_reg_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `redirect_uris` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `uri` varchar(256) NOT NULL,
  `client_id` bigint unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_clients_redirect_uris` (`client_id`),
  CONSTRAINT `fk_clients_redirect_uris` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `refresh_tokens` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `code_id` bigint unsigned NOT NULL,
  `refresh_token_jti` varchar(64) NOT NULL,
  `previous_refresh_token_jti` varchar(64) NOT NULL,
  `first_refresh_token_jti` varchar(64) NOT NULL,
  `session_identifier` varchar(64) NOT NULL,
  `refresh_token_type` varchar(16) NOT NULL,
  `scope` varchar(512) NOT NULL,
  `issued_at` datetime(6) DEFAULT NULL,
  `expires_at` datetime(6) DEFAULT NULL,
  `max_lifetime` datetime(6) DEFAULT NULL,
  `revoked` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_refresh_token_jti` (`refresh_token_jti`),
  KEY `fk_refresh_tokens_code` (`code_id`),
  CONSTRAINT `fk_refresh_tokens_code` FOREIGN KEY (`code_id`) REFERENCES `codes` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `settings` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `app_name` varchar(32) NOT NULL,
  `issuer` varchar(64) NOT NULL,
  `ui_theme` varchar(32) NOT NULL,
  `password_policy` int DEFAULT NULL,
  `self_registration_enabled` tinyint(1) NOT NULL,
  `self_registration_requires_email_verification` tinyint(1) NOT NULL,
  `token_expiration_in_seconds` int NOT NULL,
  `refresh_token_offline_idle_timeout_in_seconds` int NOT NULL,
  `refresh_token_offline_max_lifetime_in_seconds` int NOT NULL,
  `user_session_idle_timeout_in_seconds` int NOT NULL,
  `user_session_max_lifetime_in_seconds` int NOT NULL,
  `include_open_id_connect_claims_in_access_token` tinyint(1) NOT NULL,
  `session_authentication_key` longblob NOT NULL,
  `session_encryption_key` longblob NOT NULL,
  `aes_encryption_key` longblob NOT NULL,
  `smtp_host` varchar(128) DEFAULT NULL,
  `smtp_port` int DEFAULT NULL,
  `smtp_username` varchar(64) DEFAULT NULL,
  `smtp_password_encrypted` longblob,
  `smtp_from_name` varchar(64) DEFAULT NULL,
  `smtp_from_email` varchar(64) DEFAULT NULL,
  `smtp_encryption` varchar(16) DEFAULT NULL,
  `smtp_enabled` tinyint(1) NOT NULL,
  `sms_provider` varchar(32) DEFAULT NULL,
  `sms_config_encrypted` longblob,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;



CREATE TABLE `user_attributes` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `key` varchar(32) NOT NULL,
  `value` varchar(256) NOT NULL,
  `include_in_id_token` tinyint(1) NOT NULL,
  `include_in_access_token` tinyint(1) NOT NULL,
  `user_id` bigint unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_users_attributes` (`user_id`),
  CONSTRAINT `fk_users_attributes` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `user_consents` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `user_id` bigint unsigned NOT NULL,
  `client_id` bigint unsigned NOT NULL,
  `scope` varchar(512) NOT NULL,
  `granted_at` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_user_consents_user` (`user_id`),
  KEY `fk_user_consents_client` (`client_id`),
  CONSTRAINT `fk_user_consents_client` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`),
  CONSTRAINT `fk_user_consents_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `user_sessions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `session_identifier` varchar(64) NOT NULL,
  `started` datetime(6) NOT NULL,
  `last_accessed` datetime(6) NOT NULL,
  `auth_methods` varchar(64) NOT NULL,
  `acr_level` varchar(128) NOT NULL,
  `auth_time` datetime(6) NOT NULL,
  `ip_address` varchar(512) NOT NULL,
  `device_name` varchar(256) NOT NULL,
  `device_type` varchar(32) NOT NULL,
  `device_os` varchar(64) NOT NULL,
  `user_id` bigint unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_session_identifier` (`session_identifier`),
  KEY `fk_user_sessions_user` (`user_id`),
  CONSTRAINT `fk_user_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `user_session_clients` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `user_session_id` bigint unsigned NOT NULL,
  `client_id` bigint unsigned NOT NULL,
  `started` datetime(6) NOT NULL,
  `last_accessed` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_user_sessions_clients` (`user_session_id`),
  KEY `fk_user_session_clients_client` (`client_id`),  
  CONSTRAINT `fk_user_sessions_clients` FOREIGN KEY (`user_session_id`) REFERENCES `user_sessions` (`id`),
  CONSTRAINT `fk_user_session_clients_client` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `users_groups` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `group_id` bigint unsigned NOT NULL,
  `user_id` bigint unsigned NOT NULL,  
  PRIMARY KEY (`id`),
  KEY `fk_users_groups_group` (`group_id`),
  KEY `fk_users_groups_user` (`user_id`),
  CONSTRAINT `fk_users_groups_group` FOREIGN KEY (`group_id`) REFERENCES `groups` (`id`),
  CONSTRAINT `fk_users_groups_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;



CREATE TABLE `users_permissions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `user_id` bigint unsigned NOT NULL,
  `permission_id` bigint unsigned NOT NULL,  
  PRIMARY KEY (`id`),
  KEY `fk_users_permissions_user` (`user_id`),
  KEY `fk_users_permissions_permission` (`permission_id`),
  CONSTRAINT `fk_users_permissions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `fk_users_permissions_permission` FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`id`)  
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


CREATE TABLE `web_origins` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `origin` varchar(256) NOT NULL,
  `client_id` bigint unsigned NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fk_clients_web_origins` (`client_id`),
  CONSTRAINT `fk_clients_web_origins` FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- END