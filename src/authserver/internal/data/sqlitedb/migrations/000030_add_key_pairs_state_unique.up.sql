-- One key per state (#251).
--
-- key_pairs holds at most one row in each of 'current', 'next' and 'previous', and
-- every reader has always assumed it. GetCurrentSigningKey is a plain
-- WHERE state = 'current' with no ORDER BY and no LIMIT, so with two current rows it
-- returns whichever the driver yields first; /certs assigns previousKey in a loop and
-- so publishes only the last duplicate it sees; the admin console offers to revoke
-- "the previous key", singular. The assumption was enforced nowhere. idx_state, from
-- the initial migration, is a plain index on all four engines and stays as it is:
-- it serves the lookups, this one serves the invariant.
--
-- The rotation that could break the assumption is fixed separately, in the same
-- change: it now runs in one transaction with each state change written as a
-- compare-and-set. This index is what makes the invariant enforceable rather than
-- merely intended, and it is why GetCurrentSigningKey's single row is provable
-- instead of arbitrary.
--
-- THE SWEEP. Existing deployments may already carry duplicates, because until this
-- release two concurrent rotations could both insert a new 'next' row. Keeping the
-- highest id per state keeps the newest, since id is monotonic on every engine
-- (sqlite AUTOINCREMENT, mysql AUTO_INCREMENT, postgres sequence, mssql IDENTITY).
-- Extra 'next' rows are the only duplicates this defect can actually produce, and a
-- 'next' key has signed nothing, so in the reachable case the sweep destroys nothing
-- anyone can be holding a token from.
--
-- The derived table is not decoration: MySQL refuses a subquery that names the table
-- being deleted from, and wrapping it makes the same statement legal on all four
-- engines. Sweeping rather than failing on a duplicate is deliberate too. A failed
-- migration stops startup and leaves the schema version dirty, and a deployment that
-- cannot start cannot be repaired through the product.
DELETE FROM key_pairs
 WHERE id NOT IN (SELECT id FROM (SELECT MAX(id) AS id FROM key_pairs GROUP BY state) AS keep);

CREATE UNIQUE INDEX `idx_key_pairs_state` ON `key_pairs`(`state`);
