package datatests

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyPairsStateIndex000030 is the index the migration adds, on every engine.
const keyPairsStateIndex000030 = "idx_key_pairs_state"

// TestMigration000030_KeyPairsStateUnique exercises the migration that makes
// key_pairs hold at most one row per state (#251). It runs against an ISOLATED
// database of the configured dialect (see migration_testdb_helper.go): seed
// duplicates at 000029, apply 000030, and assert what survived and what the index
// now refuses.
//
// The assertions worth explaining:
//
//  1. Absent at 000029, so the index found afterwards is the one 000030 created
//     rather than one already there under a colliding name. idx_state, from the
//     initial migration, is a different index on the same column and stays.
//  2. The uniqueness flag's polarity is checked on this engine before it is trusted,
//     using idx_state as a control. Each catalog reports uniqueness differently and
//     MySQL reports it inverted (NON_UNIQUE), so "unique" would otherwise pass on an
//     engine whose flag was being read backwards, which is the one way this test
//     could report green on an index that constrains nothing. 000025's control runs
//     in the opposite polarity, which is what makes this one the right way round.
//  3. The sweep keeps exactly one row per state, and keeps the HIGHEST id of each.
//     Asserting only the count would pass with MAX(id) written as MIN(id), which is
//     the wrong end: id is monotonic on every engine, so the newest key is the one
//     the deployment is actually using.
//  4. The index covers exactly [state] and is unique. Name-only presence is not
//     enough: an index built on the wrong column, or built non-unique, would pass a
//     name check while enforcing nothing.
//  5. It bites. A second 'current' insert is refused. The catalog can report a shape
//     the engine does not enforce only if the index were somehow filtered, and this
//     is the assertion that closes that off without reading any engine's DDL back.
//  6. The down migration runs and re-applying is clean. The down is not a true
//     inverse, since the swept rows are gone for good, which the file says.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000030_KeyPairsStateUnique
func TestMigration000030_KeyPairsStateUnique(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(29), "migrate to 000029")

	// 2. Control: a known non-unique index on the same column must read as non-unique
	// here. This is what makes the "unique" assertion below mean something.
	control := describeIndex(t, h, "key_pairs", "idx_state")
	require.True(t, control.Exists, "control index idx_state must exist at 000029")
	require.False(t, control.Unique,
		"control index idx_state is non-unique on every engine; reading it as unique means the uniqueness flag is being read backwards")

	// 1. Absent before the migration.
	require.False(t, describeIndex(t, h, "key_pairs", keyPairsStateIndex000030).Exists,
		"%s must not exist at 000029", keyPairsStateIndex000030)

	// The shape probe/probe_251b_test.go.txt ran: duplicates in all three states, more
	// than two in one of them so a sweep that merely deduplicated pairs would still
	// leave a duplicate behind.
	seeded := map[string][]int64{}
	for _, s := range []struct {
		state string
		n     int
	}{{"current", 2}, {"next", 3}, {"previous", 2}} {
		for i := 0; i < s.n; i++ {
			seeded[s.state] = append(seeded[s.state], seedKeyPair000030(t, h, s.state))
		}
	}
	require.EqualValues(t, 7, countKeyPairs000030(t, h, ""), "seven rows seeded at 000029")

	require.NoError(t, h.Migrator.Migrate(30), "apply 000030")

	// 3. One row per state, and it is the highest id of that state.
	require.EqualValues(t, 3, countKeyPairs000030(t, h, ""),
		"the sweep must leave exactly one row per state")
	for state, ids := range seeded {
		require.EqualValues(t, 1, countKeyPairs000030(t, h, state),
			"exactly one %s row must survive the sweep", state)

		want := ids[len(ids)-1] // seeded in ascending id order
		var got int64
		require.NoError(t, h.SQL.QueryRow(
			fmt.Sprintf("SELECT id FROM key_pairs WHERE state = '%s'", state)).Scan(&got),
			"read the surviving %s row", state)
		assert.Equalf(t, want, got,
			"the sweep must keep the HIGHEST id in state %s (MAX(id), not MIN(id)): "+
				"id is monotonic on every engine, so the newest key is the one in use", state)
	}

	// 4 and 5.
	assertKeyPairsStateIndex000030(t, h, "after apply")

	// 6. Down, then up again.
	require.NoError(t, h.Migrator.Migrate(29), "roll back 000030")
	assert.False(t, describeIndex(t, h, "key_pairs", keyPairsStateIndex000030).Exists,
		"%s must be gone after rolling back to 000029", keyPairsStateIndex000030)

	require.NoError(t, h.Migrator.Migrate(30), "re-apply 000030")
	assertKeyPairsStateIndex000030(t, h, "after down/up round trip")
}

// assertKeyPairsStateIndex000030 checks the index's shape in the catalog and then
// checks that the engine actually enforces it.
func assertKeyPairsStateIndex000030(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()

	shape := describeIndex(t, h, "key_pairs", keyPairsStateIndex000030)

	require.Truef(t, shape.Exists, "[%s] %s is missing", phase, keyPairsStateIndex000030)
	assert.Equalf(t, []string{"state"}, shape.Columns,
		"[%s] %s must cover exactly state", phase, keyPairsStateIndex000030)
	assert.Truef(t, shape.Unique,
		"[%s] %s must be UNIQUE: it is the whole point of the migration", phase, keyPairsStateIndex000030)

	// 5. Enforced, not merely declared.
	before := countKeyPairs000030(t, h, "current")
	require.EqualValuesf(t, 1, before, "[%s] expected one current row before the duplicate attempt", phase)

	_, err := h.SQL.Exec(insertKeyPair000030SQL("current"))
	assert.Errorf(t, err, "[%s] a second row in state 'current' must be refused", phase)
	assert.EqualValuesf(t, 1, countKeyPairs000030(t, h, "current"),
		"[%s] the refused insert must leave no row behind", phase)
}

// insertKeyPair000030SQL builds an insert naming only the NOT NULL columns of the
// key_pairs table, which are the same four on all four engines. Literals rather than
// placeholders because the dialects disagree on placeholder syntax and every value
// here is test-controlled, following seedPreMigration000028User.
func insertKeyPair000030SQL(state string) string {
	return fmt.Sprintf(
		`INSERT INTO key_pairs (state, key_identifier, type, algorithm)
		 VALUES ('%s', '%s', 'RSA', 'RS256')`, state, uuid.NewString())
}

// seedKeyPair000030 inserts one key_pairs row in state and returns its id. Callers
// rely on successive calls returning ascending ids, which every engine's identity
// column provides.
func seedKeyPair000030(t *testing.T, h *isolatedDB, state string) int64 {
	t.Helper()

	q := insertKeyPair000030SQL(state)
	_, err := h.SQL.Exec(q)
	require.NoErrorf(t, err, "seed key pair in state %s", state)

	var id int64
	require.NoErrorf(t, h.SQL.QueryRow("SELECT MAX(id) FROM key_pairs").Scan(&id),
		"read back seeded key pair id")
	return id
}

// countKeyPairs000030 counts key_pairs rows, in one state or in all of them when
// state is empty.
func countKeyPairs000030(t *testing.T, h *isolatedDB, state string) int64 {
	t.Helper()

	q := "SELECT COUNT(*) FROM key_pairs"
	if state != "" {
		q = fmt.Sprintf("%s WHERE state = '%s'", q, state)
	}

	var n int64
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&n), "count key_pairs: %s", q)
	return n
}
