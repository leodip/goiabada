package datatests

import (
	"context"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000081 sits between. Literals, as for 000060: nothing in production
// code names this number.
const (
	beforeSettingsKeepSignedIn000081 = 80
	settingsKeepSignedIn000081       = 81
)

// TestMigration000081_SettingsKeepSignedIn exercises the migration that stores the "Keep users
// signed in after the browser closes" setting on the settings row (#743 decisions 3 and 4), against
// a REAL engine of the configured dialect.
//
// The properties:
//
//  1. settings.keep_signed_in does not exist at 000080; at 000081 it is NOT NULL with a default,
//     declared as this engine's file spells it.
//  2. An existing settings row reads 'ask', Let each user choose: an upgraded deployment gets the
//     same default a new one is seeded with.
//  3. A settings save the previous release makes during a rolling upgrade, naming no keep_signed_in,
//     leaves it as stored.
//  4. At head each of the three modes round-trips through the data layer.
//  5. The down migration drops the column and keeps the row, and 000081 applies again after it with
//     'ask'. On SQL Server that is the named default constraint working.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000081_SettingsKeepSignedIn
func TestMigration000081_SettingsKeepSignedIn(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// Seeded through the data layer at head, then carried down to 000080, as 000063's test does. The
	// value written is not the default, so reading 'ask' after the re-apply shows the migration put
	// it there.
	migrateToHead000063(t, h)
	settings := settings000063(20)
	settings.KeepSignedIn = record.KeepSignedInNever
	require.NoError(t, h.DB.CreateSettings(ctx, nil, settings))

	// 1.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeSettingsKeepSignedIn000081), "roll back to 000080 on %s", dbType())
	assertColumnAbsent000081(t, h, "at 000080")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, settingsKeepSignedIn000081), "apply 000081 on %s", dbType())
	assertColumn000081(t, h, "after apply")

	// 2.
	assert.Equalf(t, "ask", keepSignedInOf000081(t, h, settings.Id),
		"2. an existing installation lets each user choose on %s", dbType())

	// 3.
	_, err := h.SQL.Exec("UPDATE settings SET keep_signed_in = 'always' WHERE id = " + fmt.Sprint(settings.Id))
	require.NoErrorf(t, err, "store always on %s", dbType())
	_, err = h.SQL.Exec("UPDATE settings SET app_name = 'Previous release' WHERE id = " + fmt.Sprint(settings.Id))
	require.NoErrorf(t, err, "save the settings as the previous release does on %s", dbType())
	assert.Equalf(t, "always", keepSignedInOf000081(t, h, settings.Id),
		"3. a save naming no keep_signed_in leaves it as stored on %s", dbType())

	// 4.
	migrateToHead000063(t, h)
	stored, err := h.DB.GetSettingsById(ctx, nil, settings.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	for _, mode := range []record.KeepSignedIn{record.KeepSignedInNever, record.KeepSignedInAsk, record.KeepSignedInAlways} {
		stored.KeepSignedIn = mode
		require.NoError(t, h.DB.UpdateSettings(ctx, nil, stored))
		read, err := h.DB.GetSettingsById(ctx, nil, settings.Id)
		require.NoError(t, err)
		require.NotNil(t, read)
		assert.Equalf(t, mode, read.KeepSignedIn, "4. %s round-trips on %s", mode, dbType())
	}

	// 5.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeSettingsKeepSignedIn000081), "roll back 000081 on %s", dbType())
	assertColumnAbsent000081(t, h, "after rolling back")
	assert.Equalf(t, 1, count000062(t, h, "settings"), "5. the down keeps the settings row on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, settingsKeepSignedIn000081), "re-apply 000081 on %s", dbType())
	assertColumn000081(t, h, "after down/up round trip")
	assert.Equalf(t, "ask", keepSignedInOf000081(t, h, settings.Id),
		"5. the value dropped with the column reads ask once it is back on %s", dbType())
}

// assertColumn000081 holds the declared shape of the column. The type is compared per dialect
// because the four files deliberately differ.
func assertColumn000081(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	column := dumpTable(t, h, "settings").column(t, "keep_signed_in")
	assert.Falsef(t, column.Nullable, "[%s] settings.keep_signed_in must be NOT NULL on %s", phase, dbType())
	assert.Truef(t, column.HasDefault, "[%s] settings.keep_signed_in must carry a default on %s", phase, dbType())
	assert.Equalf(t, keepSignedInType000081(), column.Type, "[%s] settings.keep_signed_in's type on %s", phase, dbType())
}

func assertColumnAbsent000081(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	_, exists := columnNames000046(dumpTable(t, h, "settings"))["keep_signed_in"]
	assert.Falsef(t, exists, "[%s] settings.keep_signed_in must not exist on %s", phase, dbType())
}

// keepSignedInType000081 is the type each engine's 000081 file declares, written out rather than
// derived so that editing one file and forgetting the others fails here. It is the SMTP encryption
// column's, the settings row's other lower-case enumeration.
func keepSignedInType000081() string {
	switch dbType() {
	case data.MySQL:
		return "varchar(16)"
	case data.Postgres:
		return "character varying(16)"
	case data.MSSQL:
		return "nvarchar(16)"
	default:
		return "TEXT"
	}
}

// keepSignedInOf000081 reads the column with raw SQL, since the data layer can read it only at head.
func keepSignedInOf000081(t *testing.T, h *isolatedDB, settingsId int64) string {
	t.Helper()
	var mode string
	q := fmt.Sprintf("SELECT keep_signed_in FROM settings WHERE id = %d", settingsId)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&mode), "read keep_signed_in on %s", dbType())
	return mode
}
