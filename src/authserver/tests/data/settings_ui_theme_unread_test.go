package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// settings.ui_theme stays in this release for the previous one, unread, and #823 drops it (#810
// decision 2). The settings record no longer carries it: a save of any section leaves the column
// as stored, so a theme an old replica saves during a rolling upgrade is not overwritten by this
// one; and an insert, which must name the NOT NULL column with no default, fills it with the
// empty value. On isolated databases, so the raw reads and writes reach only this test's rows.

func TestUpdateSettings_LeavesUIThemeAsStored(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	settings := initialSettings("Before")
	require.NoError(t, h.DB.CreateSettings(ctx, nil, settings))

	// An old replica saves a theme after this one read the row and before it saves its own.
	loaded, err := h.DB.GetSettingsById(ctx, nil, settings.Id)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	setUIThemeUnread(t, h, settings.Id, "dark")

	loaded.AppName = "After"
	require.NoError(t, h.DB.UpdateSettings(ctx, nil, loaded))

	assert.Equalf(t, "dark", uiThemeUnread(t, h, settings.Id),
		"a settings save leaves ui_theme as stored on %s", dbType())
	stored, err := h.DB.GetSettingsById(ctx, nil, settings.Id)
	require.NoError(t, err)
	assert.Equal(t, "After", stored.AppName, "the save itself is written")
}

func TestCreateSettings_FillsUIThemeWithTheEmptyValue(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	settings := initialSettings("Ordinary")
	require.NoError(t, h.DB.CreateSettings(ctx, nil, settings))

	assert.Emptyf(t, uiThemeUnread(t, h, settings.Id), "an insert stores the empty ui_theme on %s", dbType())
}

func TestCreateInitialSettings_FillsUIThemeWithTheEmptyValue(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	settings := initialSettings("Initial")
	require.NoError(t, h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return h.DB.CreateInitialSettings(ctx, tx, settings)
	}))

	assert.Emptyf(t, uiThemeUnread(t, h, 1), "the first start stores the empty ui_theme on %s", dbType())
}

// setUIThemeUnread writes a settings row's ui_theme with raw SQL, as the previous release does.
// Bound rather than inlined, since some of the values 000065's test stores are not plain ASCII.
func setUIThemeUnread(t *testing.T, h *isolatedDB, settingsId int64, theme string) {
	t.Helper()
	q := fmt.Sprintf("UPDATE settings SET ui_theme = %s WHERE id = %s", placeholder000059(1), placeholder000059(2))
	_, err := h.SQL.Exec(q, theme, settingsId)
	require.NoErrorf(t, err, "store ui_theme %q on %s", theme, dbType())
}

func uiThemeUnread(t *testing.T, h *isolatedDB, settingsId int64) string {
	t.Helper()
	var theme string
	q := fmt.Sprintf("SELECT ui_theme FROM settings WHERE id = %d", settingsId)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&theme), "read settings.ui_theme on %s", dbType())
	return theme
}
