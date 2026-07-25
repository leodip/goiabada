CREATE TABLE http_sessions (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMP(6),
  updated_at TIMESTAMP(6),
  data TEXT,
  expires_on TIMESTAMP(6)
);
CREATE INDEX idx_httpsess_expires ON http_sessions(expires_on);
