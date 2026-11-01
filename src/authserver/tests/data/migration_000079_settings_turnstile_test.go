package datatests

import (
	"context"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000079 sits between. Literals, as for 000060: nothing in production
// code names this number.
const (
	beforeSettingsTurnstile000079 = 78
	settingsTurnstile000079       = 79
)

// TestMigration000079_SettingsTurnstile exercises the migration that stores the Cloudflare Turnstile
// challenge's switch, site key and sealed secret key on the settings row (#642 decision 1), against
// a REAL engine of the configured dialect.
//
// The properties:
//
//  1. None of the three columns exists at 000078; at 000079 the switch and the site key are NOT NULL
//     with a default and the secret key is nullable, each declared as this engine's file spells it.
//  2. An existing settings row has the challenge off, no site key and no secret key: an upgrade
//     changes nothing until an administrator turns it on.
//  3. A settings save the previous release makes during a rolling upgrade, naming none of the three
//     columns, leaves them as stored.
//  4. At head the three round-trip through the data layer, on and off.
//  5. The down migration drops the three columns and keeps the row, and 000079 applies again after
//     it with the challenge off. On SQL Server that is the named default constraints working.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000079_SettingsTurnstile
func TestMigration000079_SettingsTurnstile(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// Seeded through the data layer at head, then carried down to 000078, as 000063's test does. The
	// values written are not the defaults, so reading the defaults after the re-apply shows the
	// migration put them there.
	migrateToHead000063(t, h)
	settings := settings000063(20)
	settings.TurnstileEnabled = true
	settings.TurnstileSiteKey = "1x00000000000000000000AA"
	settings.TurnstileSecretKeyEncrypted = []byte("sealed-secret-key")
	require.NoError(t, h.DB.CreateSettings(ctx, nil, settings))

	// 1.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeSettingsTurnstile000079), "roll back to 000078 on %s", dbType())
	assertColumnsAbsent000079(t, h, "at 000078")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, settingsTurnstile000079), "apply 000079 on %s", dbType())
	assertColumns000079(t, h, "after apply")

	// 2.
	enabled, siteKey, secretKey := turnstileOf000079(t, h, settings.Id)
	assert.Falsef(t, enabled, "2. an existing installation has the challenge off on %s", dbType())
	assert.Emptyf(t, siteKey, "2. and no site key on %s", dbType())
	assert.Emptyf(t, secretKey, "2. and no secret key on %s", dbType())

	// 3.
	_, err := h.SQL.Exec("UPDATE settings SET turnstile_enabled = " + true000079() +
		", turnstile_site_key = 'stored-site-key' WHERE id = " + fmt.Sprint(settings.Id))
	require.NoErrorf(t, err, "store a site key on %s", dbType())
	_, err = h.SQL.Exec("UPDATE settings SET app_name = 'Previous release' WHERE id = " + fmt.Sprint(settings.Id))
	require.NoErrorf(t, err, "save the settings as the previous release does on %s", dbType())
	enabled, siteKey, _ = turnstileOf000079(t, h, settings.Id)
	assert.Truef(t, enabled, "3. a save naming none of the columns leaves the switch on %s", dbType())
	assert.Equalf(t, "stored-site-key", siteKey, "3. and the site key on %s", dbType())

	// 4.
	migrateToHead000063(t, h)
	stored, err := h.DB.GetSettingsById(ctx, nil, settings.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	for _, on := range []bool{true, false} {
		stored.TurnstileEnabled = on
		stored.TurnstileSiteKey = fmt.Sprintf("site-key-%v", on)
		stored.TurnstileSecretKeyEncrypted = []byte(fmt.Sprintf("sealed-%v", on))
		require.NoError(t, h.DB.UpdateSettings(ctx, nil, stored))
		read, err := h.DB.GetSettingsById(ctx, nil, settings.Id)
		require.NoError(t, err)
		require.NotNil(t, read)
		assert.Equalf(t, on, read.TurnstileEnabled, "4. the switch round-trips as %v on %s", on, dbType())
		assert.Equalf(t, fmt.Sprintf("site-key-%v", on), read.TurnstileSiteKey, "4. the site key round-trips on %s", dbType())
		assert.Equalf(t, []byte(fmt.Sprintf("sealed-%v", on)), read.TurnstileSecretKeyEncrypted,
			"4. the secret key round-trips on %s", dbType())
	}

	// 5.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeSettingsTurnstile000079), "roll back 000079 on %s", dbType())
	assertColumnsAbsent000079(t, h, "after rolling back")
	assert.Equalf(t, 1, count000062(t, h, "settings"), "5. the down keeps the settings row on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, settingsTurnstile000079), "re-apply 000079 on %s", dbType())
	assertColumns000079(t, h, "after down/up round trip")
	enabled, siteKey, secretKey = turnstileOf000079(t, h, settings.Id)
	assert.Falsef(t, enabled, "5. the switch dropped with the column reads off once it is back on %s", dbType())
	assert.Emptyf(t, siteKey, "5. the site key reads empty once it is back on %s", dbType())
	assert.Emptyf(t, secretKey, "5. the secret key reads empty once it is back on %s", dbType())
}

// assertColumns000079 holds the declared shape of the three columns. The types are compared per
// dialect because the four files deliberately differ.
func assertColumns000079(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	table := dumpTable(t, h, "settings")

	enabled := table.column(t, "turnstile_enabled")
	assert.Falsef(t, enabled.Nullable, "[%s] settings.turnstile_enabled must be NOT NULL on %s", phase, dbType())
	assert.Truef(t, enabled.HasDefault, "[%s] settings.turnstile_enabled must carry a default on %s", phase, dbType())
	assert.Equalf(t, enabledType000079(), enabled.Type, "[%s] settings.turnstile_enabled's type on %s", phase, dbType())

	siteKey := table.column(t, "turnstile_site_key")
	assert.Falsef(t, siteKey.Nullable, "[%s] settings.turnstile_site_key must be NOT NULL on %s", phase, dbType())
	assert.Truef(t, siteKey.HasDefault, "[%s] settings.turnstile_site_key must carry a default on %s", phase, dbType())
	assert.Equalf(t, siteKeyType000079(), siteKey.Type, "[%s] settings.turnstile_site_key's type on %s", phase, dbType())

	secretKey := table.column(t, "turnstile_secret_key_encrypted")
	assert.Truef(t, secretKey.Nullable, "[%s] settings.turnstile_secret_key_encrypted must be nullable on %s", phase, dbType())
	assert.Equalf(t, secretKeyType000079(), secretKey.Type,
		"[%s] settings.turnstile_secret_key_encrypted's type on %s", phase, dbType())
}

func assertColumnsAbsent000079(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	columns := columnNames000046(dumpTable(t, h, "settings"))
	for _, name := range []string{"turnstile_enabled", "turnstile_site_key", "turnstile_secret_key_encrypted"} {
		_, exists := columns[name]
		assert.Falsef(t, exists, "[%s] settings.%s must not exist on %s", phase, name, dbType())
	}
}

// enabledType000079, siteKeyType000079 and secretKeyType000079 are the types each engine's 000079
// file declares, written out rather than derived so that editing one file and forgetting the others
// fails here. They are the types the SMTP switch and password columns carry on each engine.
func enabledType000079() string {
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

func siteKeyType000079() string {
	switch dbType() {
	case data.MySQL:
		return "varchar(128)"
	case data.Postgres:
		return "character varying(128)"
	case data.MSSQL:
		return "nvarchar(128)"
	default:
		return "TEXT"
	}
}

func secretKeyType000079() string {
	switch dbType() {
	case data.MySQL:
		return "longblob"
	case data.Postgres:
		return "bytea"
	case data.MSSQL:
		return "varbinary(max)"
	default:
		return "BLOB"
	}
}

// true000079 is a true boolean literal as this engine's SQL spells one.
func true000079() string {
	if dbType() == data.Postgres {
		return "true"
	}
	return "1"
}

// turnstileOf000079 reads the three columns with raw SQL, since the data layer can read them only at
// head.
func turnstileOf000079(t *testing.T, h *isolatedDB, settingsId int64) (bool, string, []byte) {
	t.Helper()
	var enabled bool
	var siteKey string
	var secretKey []byte
	q := fmt.Sprintf("SELECT turnstile_enabled, turnstile_site_key, turnstile_secret_key_encrypted FROM settings WHERE id = %d", settingsId)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&enabled, &siteKey, &secretKey), "read the Turnstile columns on %s", dbType())
	return enabled, siteKey, secretKey
}
