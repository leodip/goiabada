-- One key per state (#251). See the sqlite migration of the same number for which
-- readers already assume it, why the sweep keeps the highest id per state, and why a
-- duplicate is swept rather than failing the migration.
DELETE FROM key_pairs
 WHERE id NOT IN (SELECT id FROM (SELECT MAX(id) AS id FROM key_pairs GROUP BY state) AS keep);

CREATE UNIQUE INDEX idx_key_pairs_state ON key_pairs(state);
