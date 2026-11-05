package datatests

import (
	"context"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000083 sits between. Literals, as for 000081: nothing in production
// code names this number.
const (
	beforeSettingsAccountDeletion000083 = 82
	settingsAccountDeletion000083       = 83
)

// TestMigration000083_SettingsAccountDeletion exercises the migration that stores the "Let users
// delete their own account" setting on the settings row (#783 decision 5), against a REAL engine
// of the configured dialect.
//
// The properties:
//
//  1. settings.account_deletion_enabled does not exist at 000082; at 000083 it is a NOT NULL
//     boolean with a default, declared as this engine's file spells it.
//  2. An existing settings row reads on: an upgraded deployment lets its users delete their own
//     account, as a new one is seeded to.
//  3. A settings save the previous release makes during a rolling upgrade, naming no
//     account_deletion_enabled, leaves it as stored.
//  4. At head both values round-trip through the data layer.
//  5. The down migration drops the column and keeps the row, and 000083 applies again after it
//     with the setting on. On SQL Server that is the named default constraint working.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000083_SettingsAccountDeletion
func TestMigration000083_SettingsAccountDeletion(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// Seeded through the data layer at head, then carried down to 000082, as 000081's test does.
	// The value written is off, not the default, so reading on after the re-apply shows the
	// migration put it there.
	migrateToHead000063(t, h)
	settings := settings000063(20)
	settings.AccountDeletionEnabled = false
	require.NoError(t, h.DB.CreateSettings(ctx, nil, settings))

	// 1.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeSettingsAccountDeletion000083), "roll back to 000082 on %s", dbType())
	assertColumnAbsent000083(t, h, "at 000082")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, settingsAccountDeletion000083), "apply 000083 on %s", dbType())
	assertColumn000083(t, h, "after apply")

	// 2.
	assert.Truef(t, accountDeletionOf000083(t, h, settings.Id),
		"2. an existing installation lets users delete their own account on %s", dbType())

	// 3.
	_, err := h.SQL.Exec("UPDATE settings SET account_deletion_enabled = " + boolLiteral000083(false) +
		" WHERE id = " + fmt.Sprint(settings.Id))
	require.NoErrorf(t, err, "turn account deletion off on %s", dbType())
	_, err = h.SQL.Exec("UPDATE settings SET app_name = 'Previous release' WHERE id = " + fmt.Sprint(settings.Id))
	require.NoErrorf(t, err, "save the settings as the previous release does on %s", dbType())
	assert.Falsef(t, accountDeletionOf000083(t, h, settings.Id),
		"3. a save naming no account_deletion_enabled leaves it as stored on %s", dbType())

	// 4.
	migrateToHead000063(t, h)
	stored, err := h.DB.GetSettingsById(ctx, nil, settings.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	for _, enabled := range []bool{true, false, true} {
		stored.AccountDeletionEnabled = enabled
		require.NoError(t, h.DB.UpdateSettings(ctx, nil, stored))
		read, err := h.DB.GetSettingsById(ctx, nil, settings.Id)
		require.NoError(t, err)
		require.NotNil(t, read)
		assert.Equalf(t, enabled, read.AccountDeletionEnabled, "4. %v round-trips on %s", enabled, dbType())
	}

	// 5.
	stored.AccountDeletionEnabled = false
	require.NoError(t, h.DB.UpdateSettings(ctx, nil, stored))
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeSettingsAccountDeletion000083), "roll back 000083 on %s", dbType())
	assertColumnAbsent000083(t, h, "after rolling back")
	assert.Equalf(t, 1, count000062(t, h, "settings"), "5. the down keeps the settings row on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, settingsAccountDeletion000083), "re-apply 000083 on %s", dbType())
	assertColumn000083(t, h, "after down/up round trip")
	assert.Truef(t, accountDeletionOf000083(t, h, settings.Id),
		"5. the value dropped with the column reads on once it is back on %s", dbType())
}

// assertColumn000083 holds the declared shape of the column. The type is compared per dialect
// because the four files deliberately differ.
func assertColumn000083(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	column := dumpTable(t, h, "settings").column(t, "account_deletion_enabled")
	assert.Falsef(t, column.Nullable, "[%s] settings.account_deletion_enabled must be NOT NULL on %s", phase, dbType())
	assert.Truef(t, column.HasDefault, "[%s] settings.account_deletion_enabled must carry a default on %s", phase, dbType())
	assert.Equalf(t, accountDeletionType000083(), column.Type, "[%s] settings.account_deletion_enabled's type on %s", phase, dbType())
}

func assertColumnAbsent000083(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	_, exists := columnNames000046(dumpTable(t, h, "settings"))["account_deletion_enabled"]
	assert.Falsef(t, exists, "[%s] settings.account_deletion_enabled must not exist on %s", phase, dbType())
}

// accountDeletionType000083 is the type each engine's 000083 file declares, written out rather than
// derived so that editing one file and forgetting the others fails here. It is pkce_required's,
// the settings row's other boolean added with a default.
func accountDeletionType000083() string {
	switch dbType() {
	case data.MySQL:
		return "tinyint(1)"
	case data.Postgres:
		return "boolean"
	case data.MSSQL:
		return "bit"
	default:
		return "BOOLEAN"
	}
}

// boolLiteral000083 is a boolean as this engine's SQL spells it: PostgreSQL refuses 0 and 1 for a
// boolean column.
func boolLiteral000083(b bool) string {
	if dbType() == data.Postgres {
		return fmt.Sprint(b)
	}
	if b {
		return "1"
	}
	return "0"
}

// accountDeletionOf000083 reads the column with raw SQL, since the data layer can read it only at
// head.
func accountDeletionOf000083(t *testing.T, h *isolatedDB, settingsId int64) bool {
	t.Helper()
	var enabled bool
	q := fmt.Sprintf("SELECT account_deletion_enabled FROM settings WHERE id = %d", settingsId)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&enabled), "read account_deletion_enabled on %s", dbType())
	return enabled
}
