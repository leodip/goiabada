package main

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/data/migrator"
	"github.com/leodip/goiabada/core/data/sqlitedb"
)

// newTestMigrator gives each test its own SQLite file database and a migrator over the real
// embedded migration set, which is what seam 3 asks for: the command observed against the runner
// it will run against in production, not a double that agrees with it. A file rather than
// :memory: because the migrations create and drop real objects across many statements.
func newTestMigrator(t *testing.T) (*migrator.Migrator, *sql.DB) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "migrate_test.db")
	db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{
		Type: "sqlite",
		DSN:  "file:" + path,
	}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })

	m, err := db.NewMigrator()
	require.NoError(t, err)
	return m, db.DB
}

func TestMigrateVersion_NeverMigratedDatabase(t *testing.T) {
	m, _ := newTestMigrator(t)
	var out bytes.Buffer

	code := runMigrate([]string{"version"}, m, rollbackFloor, &out)

	require.Equal(t, 0, code)
	assert.Contains(t, out.String(), "engine: sqlite")
	assert.Contains(t, out.String(), "000044")
	assert.Contains(t, out.String(), "never been migrated")
}

func TestMigrateVersion_ReportsWhatTheDatabaseRecords(t *testing.T) {
	m, _ := newTestMigrator(t)
	require.NoError(t, m.Up())

	var out bytes.Buffer
	code := runMigrate([]string{"version"}, m, rollbackFloor, &out)

	require.Equal(t, 0, code)
	assert.Contains(t, out.String(), "the database records schema version 000044")
	assert.NotContains(t, out.String(), "DIRTY")
}

// A dirty database is exactly when an operator runs `migrate version` first, so it has to answer
// there and say which of the two problems it is looking at.
func TestMigrateVersion_AnnouncesADirtyDatabase(t *testing.T) {
	m, sqlDB := newTestMigrator(t)
	require.NoError(t, m.Up())
	markDirty(t, m, sqlDB, 44)

	var out bytes.Buffer
	code := runMigrate([]string{"version"}, m, rollbackFloor, &out)

	require.Equal(t, 0, code)
	assert.Contains(t, out.String(), "000044")
	assert.Contains(t, out.String(), "DIRTY")
	assert.Contains(t, out.String(), "did not finish")
}

func TestMigrateTo_StepsUpToTheHeadAndPrintsThePlan(t *testing.T) {
	m, _ := newTestMigrator(t)
	var out bytes.Buffer

	code := runMigrate([]string{"to", "44"}, m, rollbackFloor, &out)

	require.Equal(t, 0, code, out.String())
	assert.Contains(t, out.String(), "current schema version: none (never migrated)")
	assert.Contains(t, out.String(), "target schema version: 000044")
	// Lowest first going up, and the whole chain is listed rather than summarised.
	assert.Contains(t, out.String(), "migrations to run, in order: 000001, ")
	assert.Contains(t, out.String(), "000044")
	assert.Contains(t, out.String(), "now at schema version 000044")

	version, dirty, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, 44, version)
	assert.False(t, dirty)
}

func TestMigrateTo_AlreadyThereIsNotAFailure(t *testing.T) {
	m, _ := newTestMigrator(t)
	require.NoError(t, m.Up())

	var out bytes.Buffer
	code := runMigrate([]string{"to", "000044"}, m, rollbackFloor, &out)

	require.Equal(t, 0, code)
	assert.Contains(t, out.String(), "already at schema version 000044")
	assert.NotContains(t, out.String(), "migrations to run")
}

// The direction the command exists for. rollbackFloor equals the head on this release, so the
// floor is lowered here rather than in production: with the constant as written no step down is
// reachable at all, and the test that matters most would be the one that could not run.
func TestMigrateTo_StepsDownUnderALoweredFloor(t *testing.T) {
	m, _ := newTestMigrator(t)
	require.NoError(t, m.Up())

	var out bytes.Buffer
	code := runMigrate([]string{"to", "000041"}, m, 24, &out)

	require.Equal(t, 0, code, out.String())
	assert.Contains(t, out.String(), "current schema version: 000044")
	assert.Contains(t, out.String(), "target schema version: 000041")
	// Highest first, these are the .down.sql files run from the top down, and the list is the
	// versions THIS engine carries rather than a count: 000042 is a MySQL migration and SQLite
	// steps straight from 000043 to 000041.
	assert.Contains(t, out.String(), "migrations to run, in order: 000044, 000043\n")
	assert.Contains(t, out.String(), "now at schema version 000041")

	version, dirty, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, 41, version)
	assert.False(t, dirty)
}

// Both spellings of the same version reach the same number, and neither is read as octal.
func TestMigrateTo_AcceptsBareAndPaddedVersions(t *testing.T) {
	for _, arg := range []string{"41", "000041"} {
		t.Run(arg, func(t *testing.T) {
			m, _ := newTestMigrator(t)
			var out bytes.Buffer

			code := runMigrate([]string{"to", arg}, m, rollbackFloor, &out)

			// Below the floor, so refused, and the refusal names the number it parsed: 000041
			// for both forms, which is what shows the padded one was not read as octal 33.
			require.Equal(t, 1, code)
			assert.Contains(t, out.String(), "refusing to migrate to 000041")
			assert.NotContains(t, out.String(), "000033")
		})
	}
}

func TestMigrateTo_RefusesATargetBelowTheRollbackFloor(t *testing.T) {
	m, _ := newTestMigrator(t)
	require.NoError(t, m.Up())

	var out bytes.Buffer
	code := runMigrate([]string{"to", "30"}, m, rollbackFloor, &out)

	require.Equal(t, 1, code)
	assert.Contains(t, out.String(), "000030")
	assert.Contains(t, out.String(), "rollback is supported between releases")
	assert.Contains(t, out.String(), "000044")

	// It refused before touching anything.
	version, _, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, 44, version)
}

func TestMigrateTo_RefusesATargetAboveTheHead(t *testing.T) {
	m, _ := newTestMigrator(t)
	require.NoError(t, m.Up())

	var out bytes.Buffer
	code := runMigrate([]string{"to", "99"}, m, rollbackFloor, &out)

	require.Equal(t, 1, code)
	assert.Contains(t, out.String(), "000099")
	assert.Contains(t, out.String(), "000044")
	assert.Contains(t, out.String(), "newer release")
}

// A dirty database is refused before the plan is printed, so nothing suggests the command is
// about to run and the message is the runner's, which carries the two legal end states.
func TestMigrateTo_RefusesADirtyDatabase(t *testing.T) {
	m, sqlDB := newTestMigrator(t)
	require.NoError(t, m.Up())
	markDirty(t, m, sqlDB, 44)

	var out bytes.Buffer
	code := runMigrate([]string{"to", "44"}, m, rollbackFloor, &out)

	require.Equal(t, 1, code)
	assert.Contains(t, out.String(), "dirty")
	assert.Contains(t, out.String(), "000044")
	assert.NotContains(t, out.String(), "migrations to run")
}

func TestRunMigrate_UsageRefusals(t *testing.T) {
	cases := []struct {
		name string
		args []string
		says string
	}{
		{"no subcommand", nil, "usage:"},
		{"unknown subcommand", []string{"sideways"}, `unknown migrate subcommand "sideways"`},
		{"version with an argument", []string{"version", "44"}, "takes no arguments"},
		{"to with no version", []string{"to"}, "exactly one version"},
		{"to with two versions", []string{"to", "44", "45"}, "exactly one version"},
		{"to with a word", []string{"to", "latest"}, `"latest" is not a schema version`},
		{"to with a negative number", []string{"to", "-1"}, `"-1" is not a schema version`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, _ := newTestMigrator(t)
			var out bytes.Buffer

			code := runMigrate(c.args, m, rollbackFloor, &out)

			// 2, not 1: a mistyped command and a database that refused need different
			// responses, and the number is what a deployment script branches on. Asserted as
			// the literal for that reason: against the constant, both sides of the comparison
			// would move together and a renumbering would pass.
			require.Equal(t, 2, code)
			assert.Contains(t, out.String(), c.says)

			// Nothing was run.
			_, _, err := m.Version()
			assert.ErrorIs(t, err, migrator.ErrNilVersion)
		})
	}
}

// markDirty leaves schema_migrations recording version at dirty, which is what an interrupted
// migration leaves behind. Written through the table rather than through the runner because the
// runner has no way to produce it deliberately, by design.
func markDirty(t *testing.T, m *migrator.Migrator, sqlDB *sql.DB, version int) {
	t.Helper()
	require.NoError(t, m.Force(version))
	// Force records the version clean, so the flag is flipped directly: the runner has no way to
	// leave a dirty row on purpose, which is the point of it.
	_, err := sqlDB.Exec("UPDATE schema_migrations SET dirty = 1")
	require.NoError(t, err)
}
