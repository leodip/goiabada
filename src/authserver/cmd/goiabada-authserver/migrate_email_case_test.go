package main

import (
	"bytes"
	"database/sql"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/datafactory"
)

// beforeLowercaseEmails is the version this command steps up FROM in these tests: the one below
// the migration that lowercases stored addresses. Derived from the constant rather than written
// as 46, so a renumbering moves both together.
const beforeLowercaseEmails = datafactory.LowercaseEmailsVersion - 1

// seedEmail writes one users row directly, at whatever version the schema is currently at.
//
// Raw SQL rather than the ORM, and only the columns that have no default: the point of these
// tests is a row the write path would refuse today, since every endpoint lowercases before it
// stores, so there is no legitimate way to produce one through the models. A legacy database
// holding one is exactly the situation migration 000047 exists for.
func seedEmail(t *testing.T, sqlDB *sql.DB, id int64, email string) {
	t.Helper()
	_, err := sqlDB.Exec(
		`INSERT INTO users (id, enabled, subject, username, email, email_verified, otp_enabled, `+
			`password_hash, phone_number_verified, created_at, updated_at) `+
			`VALUES (?, 1, ?, ?, ?, 0, 0, 'x', 0, '2020-01-01 00:00:00', '2020-01-01 00:00:00')`,
		id, "subject-"+strconv.FormatInt(id, 10), "user"+strconv.FormatInt(id, 10), email)
	require.NoErrorf(t, err, "seed users row %d with email %q", id, email)
}

// TestMigrateTo_RefusesAnEmailCaseCollisionAndLeavesTheSchemaAlone is decision 16's promise
// asserted at the entry point the plan review found unguarded.
//
// `migrate to` is the only path to the migrator that does not come through datafactory.NewDatabase: it
// opens through OpenDatabase deliberately, so that a downward step is possible. Without the
// pre-flight here, this command on a colliding database would trip the UNIQUE idx_email half way
// up the chain. That is the expensive outcome, not merely a failed command: the migrator writes a
// dirty marker before each file runs, a dirty database refuses to start with ErrDirty, and this
// command has no force verb, so recovery means hand-editing schema_migrations in SQL.
//
// So the assertions are the three halves of "left alone" rather than just the exit code: the
// recorded version did not move, the database is not dirty, and the message names the rows.
func TestMigrateTo_RefusesAnEmailCaseCollisionAndLeavesTheSchemaAlone(t *testing.T) {
	db, m, sqlDB := newTestMigrator(t)
	require.NoError(t, m.Migrate(beforeLowercaseEmails), "step up to the version below 000047")

	seedEmail(t, sqlDB, 1, "Alice@example.com")
	seedEmail(t, sqlDB, 2, "alice@example.com")

	var out bytes.Buffer
	code := runMigrate([]string{"to", strconv.Itoa(datafactory.LowercaseEmailsVersion)}, db, m, rollbackFloor, &out)

	require.Equal(t, 1, code, "a collision must refuse: %s", out.String())
	assert.Contains(t, out.String(), "users.id=1")
	assert.Contains(t, out.String(), "users.id=2")
	assert.Contains(t, out.String(), "Alice@example.com")

	version, dirty, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, beforeLowercaseEmails, version,
		"the schema must not have moved: the whole point of checking before Migrate is that the operator can fix the rows and run the same command again")
	assert.False(t, dirty,
		"a dirty database refuses to start and this command has no force verb, so leaving one behind is the outcome the check exists to prevent")
}

// TestMigrateTo_RefusesAnAddressSQLiteWillNotLowercase is decision 17 at this entry point. SQLite
// maps ASCII only in LOWER() through modernc.org/sqlite, so 000047's predicate does not even
// select this row: the migration would report success and leave an address no credential path can
// reach, since every one of them lowercases in Go first.
//
// It is the one hazard whose absence would be silent. A collision announces itself by failing the
// UNIQUE index; this one does not announce itself at all.
func TestMigrateTo_RefusesAnAddressSQLiteWillNotLowercase(t *testing.T) {
	db, m, sqlDB := newTestMigrator(t)
	require.NoError(t, m.Migrate(beforeLowercaseEmails))

	seedEmail(t, sqlDB, 1, "Ädmin@example.com")

	var out bytes.Buffer
	code := runMigrate([]string{"to", strconv.Itoa(datafactory.LowercaseEmailsVersion)}, db, m, rollbackFloor, &out)

	require.Equal(t, 1, code, "an address this engine's LOWER() will not reduce must refuse: %s", out.String())
	assert.Contains(t, out.String(), "users.id=1")
	assert.Contains(t, out.String(), "ädmin@example.com",
		"the message must say what the address has to become, because the remedy is an UPDATE the operator writes")

	version, dirty, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, beforeLowercaseEmails, version)
	assert.False(t, dirty)
}

// TestMigrateTo_LowercasesAndDoesNotRefuseWhatItCanRepair is what says the two refusals above are
// caused by the rows rather than by the pre-flight refusing every upgrade that crosses 000047. A
// mixed-case ASCII address with no twin is exactly what the migration exists to repair, and it
// must go through and be repaired.
func TestMigrateTo_LowercasesAndDoesNotRefuseWhatItCanRepair(t *testing.T) {
	db, m, sqlDB := newTestMigrator(t)
	require.NoError(t, m.Migrate(beforeLowercaseEmails))

	seedEmail(t, sqlDB, 1, "Legacy.User@Example.COM")
	seedEmail(t, sqlDB, 2, "already@example.com")

	var out bytes.Buffer
	code := runMigrate([]string{"to", strconv.Itoa(datafactory.LowercaseEmailsVersion)}, db, m, rollbackFloor, &out)

	require.Equal(t, 0, code, "nothing here is a hazard: %s", out.String())

	version, dirty, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, datafactory.LowercaseEmailsVersion, version)
	assert.False(t, dirty)

	assert.Equal(t, "legacy.user@example.com", storedEmail(t, sqlDB, 1),
		"the mixed-case address must have been lowercased, or the migration did not run and this test proves nothing about it")
	assert.Equal(t, "already@example.com", storedEmail(t, sqlDB, 2),
		"a row already lowercase must be untouched")
}

// TestMigrateTo_DoesNotCheckAStepThatDoesNotCross000047 pins the skip that keeps this check off
// every other invocation. The seeded collision would refuse if the pre-flight ran, so the step
// succeeding is what says it did not.
func TestMigrateTo_DoesNotCheckAStepThatDoesNotCross000047(t *testing.T) {
	db, m, sqlDB := newTestMigrator(t)
	require.NoError(t, m.Migrate(beforeLowercaseEmails-1))

	seedEmail(t, sqlDB, 1, "Alice@example.com")
	seedEmail(t, sqlDB, 2, "alice@example.com")

	var out bytes.Buffer
	code := runMigrate([]string{"to", strconv.Itoa(beforeLowercaseEmails)}, db, m, rollbackFloor, &out)

	require.Equal(t, 0, code,
		"this step stops below 000047, so nothing will lowercase anything and the collision is not this command's business: %s", out.String())

	version, _, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, beforeLowercaseEmails, version)
}

// TestMigrateVersion_AnswersOverACollision pins that the read-only verb stays readable on exactly
// the database the other verb refuses. It is the first thing an operator runs after meeting the
// refusal, and a check that fired here would leave them unable to see where the schema stands.
func TestMigrateVersion_AnswersOverACollision(t *testing.T) {
	db, m, sqlDB := newTestMigrator(t)
	require.NoError(t, m.Migrate(beforeLowercaseEmails))

	seedEmail(t, sqlDB, 1, "Alice@example.com")
	seedEmail(t, sqlDB, 2, "alice@example.com")

	var out bytes.Buffer
	code := runMigrate([]string{"version"}, db, m, rollbackFloor, &out)

	require.Equal(t, 0, code)
	assert.Contains(t, out.String(), "000046")
}

// TestMigrateTo_SkipsANeverMigratedDatabase pins the skip that is a correctness requirement
// rather than an optimisation: at NilVersion there is no users table, so a scan would fail and a
// fresh install would refuse to start. The database is taken all the way to head from nothing,
// which is what every fresh install does.
func TestMigrateTo_SkipsANeverMigratedDatabase(t *testing.T) {
	db, m, _ := newTestMigrator(t)

	_, _, err := m.Version()
	require.ErrorIs(t, err, migrator.ErrNilVersion, "the database must start with no recorded version")

	var out bytes.Buffer
	code := runMigrate([]string{"to", strconv.Itoa(head(m))}, db, m, rollbackFloor, &out)

	require.Equal(t, 0, code,
		"a database with no users table must migrate, or no installation could ever be created: %s", out.String())
}

// storedEmail reads one address back, raw. The ORM would work and is avoided for the reason
// seedEmail gives: these tests are about values the models are not supposed to hold.
func storedEmail(t *testing.T, sqlDB *sql.DB, id int64) string {
	t.Helper()
	var email string
	require.NoError(t, sqlDB.QueryRow(`SELECT email FROM users WHERE id = ?`, id).Scan(&email))
	return email
}
