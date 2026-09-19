CREATE TABLE `http_sessions` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `data` longtext,
  `expires_on` datetime(6) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_httpsess_expires` (`expires_on`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
