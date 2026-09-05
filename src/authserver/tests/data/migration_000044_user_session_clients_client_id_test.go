package datatests

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userSessionClientsClientIdIndex000044 is the name all four engines carry after 000044: three
// create it, and MySQL renames the index InnoDB built for the foreign key.
const userSessionClientsClientIdIndex000044 = "idx_user_session_clients_client_id"

// innodbForeignKeyIndex000044 is the name MySQL carried before 000044, declared inline by the
// initial migration to satisfy InnoDB's requirement that a foreign key's columns be indexed.
const innodbForeignKeyIndex000044 = "fk_user_session_clients_client"

// TestMigration000044_UserSessionClientsClientIdIndex is #139's index, and it takes two shapes
// because the migration does: SQLite, PostgreSQL and SQL Server CREATE it, and MySQL RENAMEs the
// index it already had.
//
// What reads it. DeleteClient takes the client's row and then reads every association naming that
// client, so it can take those sessions' rows before its cascade wants them. On SQL Server, whose
// READ COMMITTED is lock-based, the full table scan that read would otherwise be takes shared
// locks across the association rows of OTHER clients' sessions on its way past them. A change
// whose whole purpose is to remove a blocking edge must not introduce one.
//
// Why MySQL is renamed rather than left alone. The index is the same index either way, so nothing
// about query planning changes. What changes is that a later migration can say
// DROP INDEX idx_user_session_clients_client_id on all four engines rather than on three, which
// is the failure #284's name comparison exists to catch, and it is why the schema-parity
// allowlist's InnoDB rule covers one place fewer after this.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000044_UserSessionClientsClientIdIndex
func TestMigration000044_UserSessionClientsClientIdIndex(t *testing.T) {
	h := newIsolatedDB(t)

	// The version immediately below 000044 differs per engine, because migrations land on the
	// engines that need them: sqlite's last is 000043, mysql's 000042, postgres's 000039 and SQL
	// Server's 000040. Migrate refuses a target its own source does not carry, so the predecessor
	// has to be named rather than assumed to be 43.
	previous := previousVersion000044()

	require.NoErrorf(t, h.Migrator.Migrate(previous), "migrate to %06d", previous)

	// The control, which is what makes the uniqueness reading below mean anything. Each catalog
	// reports uniqueness differently and MySQL reports it inverted, so an index read as
	// non-unique by a flag being read backwards would otherwise pass. idx_refresh_token_jti is
	// UNIQUE on all four engines; this is 000036's polarity guard, run for the same reason.
	control := describeIndex(t, h, "refresh_tokens", "idx_refresh_token_jti")
	require.True(t, control.Exists, "control index idx_refresh_token_jti must exist below 000044")
	require.True(t, control.Unique,
		"idx_refresh_token_jti is UNIQUE on every engine; reading it as non-unique means the uniqueness flag is being read backwards")

	before := describeIndex(t, h, "user_session_clients", userSessionClientsClientIdIndex000044)
	require.Falsef(t, before.Exists,
		"%s must not exist below 000044 on any engine: on MySQL the column is indexed under %s, and on the other three it is not indexed at all",
		userSessionClientsClientIdIndex000044, innodbForeignKeyIndex000044)

	if isMySQL000044() {
		require.True(t, describeIndex(t, h, "user_session_clients", innodbForeignKeyIndex000044).Exists,
			"MySQL indexes the column below 000044 under %s, which is the whole reason its migration is a rename",
			innodbForeignKeyIndex000044)
	}

	require.NoError(t, h.Migrator.Migrate(44), "apply 000044")
	assertUserSessionClientsClientIdIndex000044(t, h, "after apply")

	require.NoErrorf(t, h.Migrator.Migrate(previous), "roll back 000044 to %06d", previous)
	assert.Falsef(t, describeIndex(t, h, "user_session_clients", userSessionClientsClientIdIndex000044).Exists,
		"%s must be gone after rolling back 000044", userSessionClientsClientIdIndex000044)
	if isMySQL000044() {
		assert.Truef(t, describeIndex(t, h, "user_session_clients", innodbForeignKeyIndex000044).Exists,
			"the down migration renames MySQL's index back to %s rather than dropping it: InnoDB would refuse to leave the foreign key uncovered",
			innodbForeignKeyIndex000044)
	}

	require.NoError(t, h.Migrator.Migrate(44), "re-apply 000044")
	assertUserSessionClientsClientIdIndex000044(t, h, "after down/up round trip")
}

// assertUserSessionClientsClientIdIndex000044 checks the shape rather than the name alone: an
// index built over the wrong column would pass a name check while doing nothing for the scan this
// exists to remove.
func assertUserSessionClientsClientIdIndex000044(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()

	shape := describeIndex(t, h, "user_session_clients", userSessionClientsClientIdIndex000044)

	require.Truef(t, shape.Exists, "[%s] %s is missing on %s",
		phase, userSessionClientsClientIdIndex000044, dbType())
	assert.Equalf(t, []string{"client_id"}, shape.Columns,
		"[%s] %s must cover exactly client_id", phase, userSessionClientsClientIdIndex000044)
	assert.Falsef(t, shape.Unique,
		"[%s] %s must NOT be unique: one client is named by many sessions. The unique constraint on the PAIR is #249's, and a different index",
		phase, userSessionClientsClientIdIndex000044)

	if isMySQL000044() {
		assert.Falsef(t, describeIndex(t, h, "user_session_clients", innodbForeignKeyIndex000044).Exists,
			"[%s] %s is a RENAME on MySQL, so the old name must be gone rather than a second index left beside it",
			phase, innodbForeignKeyIndex000044)
	}
}

func isMySQL000044() bool {
	return dbType() == "mysql"
}

// previousVersion000044 is the highest migration each engine carries below 000044. Written out
// rather than derived, so that adding a file to one engine and forgetting this list fails here
// with a version mismatch rather than silently testing the wrong starting point.
func previousVersion000044() uint {
	switch dbType() {
	case "mysql":
		return 42
	case "postgres":
		return 39
	case "mssql":
		return 40
	default:
		return 43
	}
}
