package datafactory

import (
	"errors"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/core/data"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// row is one users row as the pre-flight reads it, with the engine's LOWER() agreeing with Go's.
// Every hazard case below varies exactly one thing from this, which is what makes the passing
// cases load-bearing: a check that refused everything would satisfy the refusals on its own.
func row(id int64, email string) models.EmailCaseRow {
	return models.EmailCaseRow{Id: id, Email: email, EngineLowered: strings.ToLower(email)}
}

// divergentRow is a row this engine's LOWER() does not reduce the way Go does: it is what SQLite
// answers for any non-ASCII uppercase letter and what SQL Server answers for U+1E9E and U+212A,
// and the reason the check compares rather than carrying a character list.
func divergentRow(id int64, email string, engineLowered string) models.EmailCaseRow {
	return models.EmailCaseRow{Id: id, Email: email, EngineLowered: engineLowered}
}

// TestCheckEmailCaseBeforeMigrating_Skips pins the three states in which the check reads nothing
// at all. Each asserts through an unstubbed mock: mockery fails the test on an unexpected call,
// so "ScanEmailCase was never called" is asserted by the absence of an expectation rather than
// by a flag the production code could stop setting.
//
// The skips are not an optimisation. The NilVersion case is a correctness requirement: a database
// that has never been migrated has no users table, so a scan would fail and a fresh install would
// refuse to start. The other two are what keep the check off every restart and every downward
// step once the upgrade is behind the deployment.
func TestCheckEmailCaseBeforeMigrating_Skips(t *testing.T) {
	tests := []struct {
		name     string
		recorded int
		target   int
		why      string
	}{
		{
			name:     "a database that has never been migrated",
			recorded: migrator.NilVersion,
			target:   LowercaseEmailsVersion,
			why:      "there is no users table yet, so a scan would fail and a fresh install would refuse to start",
		},
		{
			name:     "a database already at 000047",
			recorded: LowercaseEmailsVersion,
			target:   LowercaseEmailsVersion,
			why:      "the migration has run; it does not run twice, so there is nothing to be ahead of",
		},
		{
			name:     "a database already above 000047",
			recorded: LowercaseEmailsVersion + 3,
			target:   LowercaseEmailsVersion + 5,
			why:      "same as above, and this is what every ordinary restart looks like once the upgrade is behind the deployment",
		},
		{
			name:     "an upward step that stops short of 000047",
			recorded: LowercaseEmailsVersion - 3,
			target:   LowercaseEmailsVersion - 1,
			why:      "the step does not cross the migration, so nothing will lowercase anything",
		},
		{
			name:     "a downward step",
			recorded: LowercaseEmailsVersion + 2,
			target:   LowercaseEmailsVersion - 2,
			why:      "`migrate to` steps down as well, and the down migration is a no-op that cannot collide with anything",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := mocks_data.NewDatabase(t)

			err := CheckEmailCaseBeforeMigrating(db, tc.recorded, tc.target)

			assert.NoErrorf(t, err, "must not refuse: %s", tc.why)
		})
	}
}

// TestCheckEmailCaseBeforeMigrating_RefusesACollision pins decision 16's refusal and, just as
// much, its message. The operator's whole remedy is in that string: they have to find the rows
// and decide which account keeps the address, and this server deliberately will not choose for
// them, so a message naming one row of a pair turns one outage into two.
func TestCheckEmailCaseBeforeMigrating_RefusesACollision(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.EXPECT().ScanEmailCase().Return([]models.EmailCaseRow{
		row(1, "Alice@example.com"),
		row(2, "alice@example.com"),
		row(3, "bob@example.com"),
	}, nil)

	err := CheckEmailCaseBeforeMigrating(db, LowercaseEmailsVersion-1, LowercaseEmailsVersion)

	require.Error(t, err,
		"two addresses differing only by case cannot both survive the UPDATE, so the migration would trip idx_email and leave the schema dirty")
	msg := err.Error()
	assert.Contains(t, msg, "users.id=1", "the message must name the first colliding row")
	assert.Contains(t, msg, "users.id=2", "the message must name the second colliding row, or the operator fixes half the problem and meets this again")
	assert.Contains(t, msg, "Alice@example.com", "an id alone is not something an operator can act on without a query")
	assert.Contains(t, msg, "alice@example.com")
	assert.NotContains(t, msg, "bob@example.com",
		"a row that collides with nothing must not be named, or the operator cannot tell which rows need fixing")
	assert.Contains(t, msg, "not dirty",
		"the operator has to know the database was left alone, or their next move is a recovery they do not need")
}

// TestCheckEmailCaseBeforeMigrating_RefusesAnAddressTheEngineWillNotReduce pins decision 17, and
// the plan's correction to it: the divergence is two engines rather than one, so the rule is a
// comparison and never a character list.
//
// Both rows below carry a character the engine leaves alone. Measured, U+1E9E is exactly this on
// SQL Server at the collation 000040 installs and on SQLite through modernc.org/sqlite, while
// MySQL and PostgreSQL reduce it. The migration reports success over such a row and leaves it
// unreachable by every credential path, all of which lowercase in Go first, which is the silent
// outcome this refusal exists to prevent.
func TestCheckEmailCaseBeforeMigrating_RefusesAnAddressTheEngineWillNotReduce(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.EXPECT().ScanEmailCase().Return([]models.EmailCaseRow{
		row(1, "alice@example.com"),
		// SQL Server and SQLite both leave U+1E9E alone; Go maps it to U+00DF.
		divergentRow(2, "ẞ@example.com", "ẞ@example.com"),
		// SQLite leaves every non-ASCII uppercase letter alone, so the local part is untouched
		// while the ASCII domain is folded. A row can be partly reduced and still be wrong.
		divergentRow(3, "ÄDMIN@EXAMPLE.com", "Ädmin@example.com"),
	}, nil)

	err := CheckEmailCaseBeforeMigrating(db, LowercaseEmailsVersion-1, LowercaseEmailsVersion)

	require.Error(t, err, "the migration cannot reduce these rows, so it would report success and leave them unreachable")
	msg := err.Error()
	assert.Contains(t, msg, "users.id=2")
	assert.Contains(t, msg, "users.id=3",
		"a row the engine reduced only partly is as unreachable as one it did not touch")
	assert.NotContains(t, msg, "users.id=1",
		"a row the engine and Go agree about must not be named")
	assert.Contains(t, msg, strings.ToLower("ẞ@example.com"),
		"the message must say what the address has to become, since the remedy is an UPDATE the operator writes by hand")
}

// TestCheckEmailCaseBeforeMigrating_PassesACleanTable is what says the refusals above are caused
// by the rows rather than by the check refusing whatever it is given. It carries the shapes
// closest to a hazard without being one: an address the migration WILL repair, and two addresses
// that differ by more than case.
func TestCheckEmailCaseBeforeMigrating_PassesACleanTable(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.EXPECT().ScanEmailCase().Return([]models.EmailCaseRow{
		row(1, "alice@example.com"),
		row(2, "Bob@example.com"),
		row(3, "bobby@example.com"),
	}, nil)

	assert.NoError(t, CheckEmailCaseBeforeMigrating(db, LowercaseEmailsVersion-1, LowercaseEmailsVersion),
		"a mixed-case address with no twin is exactly what 000047 exists to repair, and two addresses differing by more than case are not a collision")
}

// TestCheckEmailCaseBeforeMigrating_PassesAnEmptyTable covers the deployment that has a users
// table and nothing in it, which is every install between the first migration and the seeder.
func TestCheckEmailCaseBeforeMigrating_PassesAnEmptyTable(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.EXPECT().ScanEmailCase().Return(nil, nil)

	assert.NoError(t, CheckEmailCaseBeforeMigrating(db, LowercaseEmailsVersion-1, LowercaseEmailsVersion))
}

// TestCheckEmailCaseBeforeMigrating_AScanFailureIsFatal pins the fail-closed direction. A read
// that failed says nothing about the data, so treating it as "no hazard found" would migrate the
// database this check exists to stop, and the operator would meet ErrDirty instead of a message.
func TestCheckEmailCaseBeforeMigrating_AScanFailureIsFatal(t *testing.T) {
	boom := errors.New("storage is unavailable")
	db := mocks_data.NewDatabase(t)
	db.EXPECT().ScanEmailCase().Return(nil, boom)

	err := CheckEmailCaseBeforeMigrating(db, LowercaseEmailsVersion-1, LowercaseEmailsVersion)

	require.Error(t, err, "an unreadable users table must stop the migration rather than be read as clean")
	assert.Contains(t, err.Error(), "unable to read stored email addresses",
		"the message must name what failed: this is the only thing the operator is told")
	assert.ErrorIs(t, err, boom, "the cause must survive, or the storage failure is invisible under a message about email")
}

// TestPreflightEmailCase_PassesADatabaseWithNoMigrator covers preflightEmailCase's one leniency:
// a handle that cannot produce a migrator is passed rather than refused.
//
// It is deliberate and therefore earns a case. The recorded version is what decides whether the
// check runs at all, and a database that cannot say what version it is at cannot be judged; every
// production handle is one of the four engines and does implement MigratorProvider, so the arm is
// reached only by a substitute, which is exactly what a generated mock of data.Database is. If
// someone puts NewMigrator on the Database interface, this case goes red and says so rather than
// quietly starting to exercise the other arms against a mock.
func TestPreflightEmailCase_PassesADatabaseWithNoMigrator(t *testing.T) {
	db := mocks_data.NewDatabase(t)

	var _ data.Database = db
	_, isProvider := any(db).(MigratorProvider)
	require.False(t, isProvider,
		"the mock must not implement MigratorProvider, or this test exercises the migrator arm while claiming to cover the leniency")

	assert.NoError(t, preflightEmailCase(db),
		"a database that cannot produce a migrator is passed, because the recorded version is what decides whether the check applies")
}
