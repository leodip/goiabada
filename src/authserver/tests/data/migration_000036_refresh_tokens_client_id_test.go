package datatests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refreshTokensClientIdIndex000036 is the index SQLite was missing, and the name the
// other three engines have carried since their own 000011.
const refreshTokensClientIdIndex000036 = "idx_refresh_tokens_client_id"

// TestMigration000036_RefreshTokensClientIdIndex is goal 1 of #282 stated as a test:
// refresh_tokens(client_id) is indexed on all four engines. It runs against an ISOLATED
// database of the configured dialect (see migration_testdb_helper.go).
//
// The migration file exists on SQLite alone, because the other three already have the
// index, so this test takes two shapes. On SQLite it is the usual migration shape: absent
// at 000035, present at 000036, gone again after the down, back after a re-apply. On the
// other three it asserts the state at 000035 and never calls Migrate past it, since
// Migrate refuses a target version the engine's source does not carry.
//
// Two assertions are worth explaining:
//
//  1. The control. idx_refresh_token_jti is UNIQUE on all four engines, so reading it as
//     unique here is what makes "the client_id index is non-unique" mean something: each
//     catalog reports uniqueness differently and MySQL reports it inverted, so a
//     non-unique reading would otherwise pass on an engine whose flag was being read
//     backwards. This is the polarity guard migration_000030 established, run in the
//     opposite direction.
//  2. The key columns, not just the name. An index built on the wrong column would pass a
//     name check while doing nothing for the scan this exists to remove.
//
// Stage 3's rebuild of refresh_tokens has to recreate this index; that is what makes this
// test worth keeping rather than a one-off check of the migration.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000036_RefreshTokensClientIdIndex
func TestMigration000036_RefreshTokensClientIdIndex(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(35), "migrate to 000035")

	// 1. Control.
	control := describeIndex(t, h, "refresh_tokens", "idx_refresh_token_jti")
	require.True(t, control.Exists, "control index idx_refresh_token_jti must exist at 000035")
	require.True(t, control.Unique,
		"control index idx_refresh_token_jti is UNIQUE on every engine; reading it as non-unique means the uniqueness flag is being read backwards")

	if !isSQLite000036() {
		assertRefreshTokensClientIdIndex000036(t, h, "at 000035")
		return
	}

	require.False(t, describeIndex(t, h, "refresh_tokens", refreshTokensClientIdIndex000036).Exists,
		"%s must not exist on SQLite at 000035: that absence is the divergence #282 reports",
		refreshTokensClientIdIndex000036)

	require.NoError(t, h.Migrator.Migrate(36), "apply 000036")
	assertRefreshTokensClientIdIndex000036(t, h, "after apply")

	require.NoError(t, h.Migrator.Migrate(35), "roll back 000036")
	assert.False(t, describeIndex(t, h, "refresh_tokens", refreshTokensClientIdIndex000036).Exists,
		"%s must be gone after rolling back to 000035", refreshTokensClientIdIndex000036)

	require.NoError(t, h.Migrator.Migrate(36), "re-apply 000036")
	assertRefreshTokensClientIdIndex000036(t, h, "after down/up round trip")
}

// assertRefreshTokensClientIdIndex000036 checks the index's shape in the catalog: present,
// covering exactly client_id, and not unique. Not unique matters as much as present, since
// a client holds many refresh tokens and a unique index here would refuse the second one.
func assertRefreshTokensClientIdIndex000036(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()

	shape := describeIndex(t, h, "refresh_tokens", refreshTokensClientIdIndex000036)

	require.Truef(t, shape.Exists, "[%s] %s is missing on %s",
		phase, refreshTokensClientIdIndex000036, dbType())
	assert.Equalf(t, []string{"client_id"}, shape.Columns,
		"[%s] %s must cover exactly client_id", phase, refreshTokensClientIdIndex000036)
	assert.Falsef(t, shape.Unique,
		"[%s] %s must NOT be unique: a client holds many refresh tokens",
		phase, refreshTokensClientIdIndex000036)
}

func isSQLite000036() bool {
	return dbType() == "" || dbType() == "sqlite"
}
