package datatests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// familyIndexName000025 is the index the migration adds, on every engine.
const familyIndexName000025 = "idx_refresh_tokens_first_refresh_token_jti"

// TestMigration000025_RefreshTokenFamilyIndex exercises the migration that indexes
// the rotation family identifier (#128). It runs against an ISOLATED database of the
// configured dialect (see migration_testdb_helper.go): migrate to 000024, assert the
// index is absent, apply 000025, and assert.
//
// The assertions worth explaining:
//
//  1. Absent at 000024, so the index this test finds afterwards is the one 000025
//     created rather than one that was already there under a colliding name.
//  2. Present afterwards, covering EXACTLY first_refresh_token_jti, and NOT UNIQUE.
//     Name-only presence is not enough. Replay containment matches on
//     `first_refresh_token_jti = ?`, so an index built on the wrong column would leave
//     that query scanning the table while passing a name check. UNIQUE would be worse
//     than useless: every member of a rotation family carries the same value by
//     design, so a unique index would reject the second member of every family and
//     break rotation entirely, and no other test in the suite creates two family
//     members on one isolated database to notice.
//  3. The polarity of the uniqueness flag is checked on this engine before it is
//     trusted, using idx_refresh_token_jti as a control. Each catalog reports
//     uniqueness differently and MySQL reports it inverted, so an assertion of
//     "not unique" would otherwise pass on an engine whose flag was being read
//     backwards, which is the one way this test could report green on a broken index.
//  4. The down migration works, and re-applying is clean. Nothing else in the suite
//     executes a down migration except the 000024 test.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000025_RefreshTokenFamilyIndex
func TestMigration000025_RefreshTokenFamilyIndex(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(24), "migrate to 000024")

	// 3. Control: a known-UNIQUE index on the same table must read as unique here.
	// This is what makes the "not unique" assertion below mean something.
	control := describeIndex(t, h, "refresh_tokens", "idx_refresh_token_jti")
	require.True(t, control.Exists, "control index idx_refresh_token_jti must exist at 000024")
	require.True(t, control.Unique,
		"control index idx_refresh_token_jti is UNIQUE on every engine; reading it as non-unique means the uniqueness flag is being read backwards")

	// 1. Absent before the migration.
	assert.False(t, describeIndex(t, h, "refresh_tokens", familyIndexName000025).Exists,
		"%s must not exist at 000024", familyIndexName000025)

	require.NoError(t, h.Migrator.Migrate(25), "apply 000025")

	// 2. Present, on the right column, non-unique.
	assertFamilyIndexShape000025(t, h, "after apply")

	// 4. Down, then up again.
	require.NoError(t, h.Migrator.Migrate(24), "roll back 000025")
	assert.False(t, describeIndex(t, h, "refresh_tokens", familyIndexName000025).Exists,
		"%s must be gone after rolling back to 000024", familyIndexName000025)

	require.NoError(t, h.Migrator.Migrate(25), "re-apply 000025")
	assertFamilyIndexShape000025(t, h, "after down/up round trip")
}

func assertFamilyIndexShape000025(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()

	shape := describeIndex(t, h, "refresh_tokens", familyIndexName000025)

	require.Truef(t, shape.Exists, "[%s] %s is missing", phase, familyIndexName000025)
	assert.Equalf(t, []string{"first_refresh_token_jti"}, shape.Columns,
		"[%s] %s must cover exactly first_refresh_token_jti", phase, familyIndexName000025)
	assert.Falsef(t, shape.Unique,
		"[%s] %s must NOT be unique: every member of a rotation family shares the value",
		phase, familyIndexName000025)
}
