package datatests

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/bootstrap"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000065 sits between. Literals, as for 000061: nothing in production
// code names this number.
const (
	beforeUIThemeLightOrDark000065 = 64
	uiThemeLightOrDark000065       = 65
)

// uiThemes000065 is every value the settings could hold before 000065, with the theme it becomes:
// the 32 daisyUI themes the admin API accepted, by the color-scheme each declared in the stylesheet
// they were drawn from, the empty value, which drew the pages dark, and values no list offered,
// which daisyUI drew in its default light theme.
var uiThemes000065 = []struct{ stored, want string }{
	{"dark", "dark"}, {"synthwave", "dark"}, {"halloween", "dark"}, {"forest", "dark"},
	{"aqua", "dark"}, {"black", "dark"}, {"luxury", "dark"}, {"dracula", "dark"},
	{"business", "dark"}, {"night", "dark"}, {"coffee", "dark"}, {"dim", "dark"},
	{"sunset", "dark"},
	{"light", "light"}, {"cupcake", "light"}, {"bumblebee", "light"}, {"emerald", "light"},
	{"corporate", "light"}, {"retro", "light"}, {"cyberpunk", "light"}, {"valentine", "light"},
	{"garden", "light"}, {"lofi", "light"}, {"pastel", "light"}, {"fantasy", "light"},
	{"wireframe", "light"}, {"cmyk", "light"}, {"autumn", "light"}, {"acid", "light"},
	{"lemonade", "light"}, {"winter", "light"}, {"nord", "light"},
	{"", "dark"},
	{"not-a-theme", "light"},
	// Compared exactly on every engine: a value differing from a dark theme's name by case, by a
	// trailing space or by an ignorable character is one no list offered.
	{"Dark", "light"},
	{"dark ", "light"},
	{"da\u00adrk", "light"},
}

// TestMigration000065_UIThemeLightOrDark exercises the backfill that maps a stored daisyUI theme to
// one of the two themes left when daisyUI went, against a REAL engine of the configured dialect
// (see migration_testdb_helper_test.go). The settings hold empty (automatic), "light" or "dark"
// since (#617).
//
// The properties:
//
//  1. Each of the 32 daisyUI themes becomes "dark" when daisyUI drew it dark and "light" otherwise.
//  2. The empty value becomes "dark", the look it had: until 000065 it drew the pages dark.
//  3. Any other value becomes "light", compared exactly: one differing from a dark theme's name only
//     by case, a trailing space or a character a linguistic collation ignores included.
//  4. The down migration changes nothing, and 000065 applies again after it.
//  5. A later start, which has nothing to migrate, leaves the values as they are, an empty value
//     written after 000065 included: that one is the automatic theme, and is not mapped to dark.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000065_UIThemeLightOrDark
func TestMigration000065_UIThemeLightOrDark(t *testing.T) {
	ctx := context.Background()
	h := newIsolatedDB(t)

	// Seeded through the ORM at head, then carried down to 000064 and back up, as 000061's test
	// does and for its reason: the ORM writes every column the record carries. 000065's down is a
	// no-op, so the rows keep what the seed wrote until the up runs again. One settings row per
	// value, which no constraint refuses, so the one up is held to every value at once.
	migrateToHead000065(t, h)
	ids := make([]int64, len(uiThemes000065))
	for i, c := range uiThemes000065 {
		settings := settings000065(c.stored)
		require.NoErrorf(t, h.DB.CreateSettings(ctx, nil, settings), "seed a settings row holding %q on %s", c.stored, dbType())
		ids[i] = settings.Id
	}

	// 4. Down to 000064 changes nothing.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeUIThemeLightOrDark000065), "roll back to 000064 on %s", dbType())
	for i, c := range uiThemes000065 {
		assert.Equalf(t, c.stored, uiThemeOf000065(t, h, ids[i]), "the no-op down kept %q on %s", c.stored, dbType())
	}

	// 1 to 3. The up's backfill.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, uiThemeLightOrDark000065), "apply 000065 on %s", dbType())
	for i, c := range uiThemes000065 {
		assert.Equalf(t, c.want, uiThemeOf000065(t, h, ids[i]), "a stored %q becomes %q on %s", c.stored, c.want, dbType())
	}

	// 5. An administrator chooses the automatic theme after the upgrade, and the server starts again.
	// The row is written at head, since the ORM writes every column the record carries, a column a
	// later migration adds to settings included (000079).
	migrateToHead000065(t, h)
	automatic := settings000065("")
	require.NoError(t, h.DB.CreateSettings(ctx, nil, automatic))
	migrateToHead000065(t, h)
	assert.Emptyf(t, uiThemeOf000065(t, h, automatic.Id), "a later start leaves the automatic theme alone on %s", dbType())
	for i, c := range uiThemes000065 {
		assert.Equalf(t, c.want, uiThemeOf000065(t, h, ids[i]), "a later start leaves %q as %q on %s", c.stored, c.want, dbType())
	}
}

// TestSeed_ANewInstallationFollowsTheDevice holds a fresh deployment to the automatic theme, the
// empty value, on every engine: the seed runs after every migration, 000065 included, so nothing
// maps its empty value to dark (#617).
func TestSeed_ANewInstallationFollowsTheDevice(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	outcome, err := bootstrap.Run(ctx, h.DB, dataCipher, seedConfig("admin@example.com"))
	require.NoError(t, err)
	require.Equal(t, bootstrap.Continue, outcome)

	settings, err := h.DB.GetSettingsById(ctx, nil, 1)
	require.NoError(t, err)
	require.NotNil(t, settings)
	assert.Emptyf(t, settings.UITheme, "a new installation stores the automatic theme on %s", dbType())

	migrateToHead000065(t, h)
	assert.Emptyf(t, uiThemeOf000065(t, h, settings.Id), "and keeps it on the next start on %s", dbType())
}

func migrateToHead000065(t *testing.T, h *isolatedDB) {
	t.Helper()
	if err := h.Migrator.Up(context.Background()); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoErrorf(t, err, "migrate to head on %s", dbType())
	}
}

func settings000065(uiTheme string) *record.Settings {
	return &record.Settings{
		AppName:                         "Migration 000065",
		Issuer:                          "https://m65.test",
		UITheme:                         uiTheme,
		PasswordPolicy:                  record.PasswordPolicyLow,
		TokenExpirationInSeconds:        300,
		UserSessionIdleTimeoutInSeconds: 7200,
		UserSessionMaxLifetimeInSeconds: 86400,
		MaxUserSessionsPerUser:          20,
		AESEncryptionKeyLegacy:          []byte{},
		SMTPPasswordEncrypted:           []byte{},
	}
}

func uiThemeOf000065(t *testing.T, h *isolatedDB, settingsId int64) string {
	t.Helper()
	var theme string
	q := fmt.Sprintf("SELECT ui_theme FROM settings WHERE id = %d", settingsId)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&theme), "read settings.ui_theme on %s", dbType())
	return theme
}
