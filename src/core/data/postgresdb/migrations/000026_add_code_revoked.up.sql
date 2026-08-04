-- Durable session termination (#129). See the sqlite migration of the same number
-- for what the column means, why the marker sits on the code, and why existing rows
-- land at false.
ALTER TABLE codes ADD COLUMN revoked boolean NOT NULL DEFAULT false;
