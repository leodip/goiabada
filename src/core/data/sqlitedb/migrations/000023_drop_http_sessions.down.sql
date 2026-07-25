CREATE TABLE http_sessions (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  `data` longtext,
  expires_on DATETIME
);
CREATE INDEX `idx_httpsess_expires` ON `http_sessions`(`expires_on`);
