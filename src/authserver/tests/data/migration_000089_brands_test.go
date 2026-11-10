package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000089 sits between. Literals: nothing in production code names this
// number.
const (
	beforeBrands000089 = 88
	brands000089       = 89
)

// uiThemes000089 is what settings.ui_theme can hold when 000089 runs, with the appearance the
// default brand it creates gets and the value the down migration writes back. Light and dark map to
// themselves and anything else to automatic, compared exactly (#810 decision 5); the down writes
// the brand's appearance back, automatic as the empty value ui_theme stores it as (decision 2).
var uiThemes000089 = []struct{ stored, appearance, writtenBack string }{
	{"light", "light", "light"},
	{"dark", "dark", "dark"},
	{"", "auto", ""},
	{"not-a-theme", "auto", ""},
	{"Dark", "auto", ""},
	{"dark ", "auto", ""},
}

// TestMigration000089_Brands exercises the migration that stores brands and points the settings row
// at the default one (#810 decisions 1, 2 and 5), against a REAL engine of the configured dialect
// (see migration_testdb_helper_test.go).
//
// The properties:
//
//  1. Before 000089 there is no brands table and no settings.default_brand_id.
//  2. An installation that had a theme gets one brand, named Default, on Blueberry, whose
//     appearance is the stored light or dark, and automatic for anything else; the settings row
//     points at it; and ui_theme is left as it was, for the previous release still reading it.
//  3. A new installation, migrated before its first start, has no settings row and gets no brand:
//     the seed writes it.
//  4. The brand's name is unique, the pointer is nullable, and the foreign key refuses deleting the
//     brand it names.
//  5. A settings save the previous release makes during a rolling upgrade, naming neither the
//     pointer nor the brands, leaves both as they are.
//  6. The down migration writes the default brand's appearance back into ui_theme and drops the
//     pointer and the table; 000089 applies again after it.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000089_Brands
func TestMigration000089_Brands(t *testing.T) {
	ctx := context.Background()
	h := migratedIsolatedDB(t)

	// 3. Migrated to head with no settings row, as a new installation is before its seed.
	assertBrandsTable000089(t, h, "on a new installation")
	assert.Equalf(t, 0, count000062(t, h, "brands"), "3. a new installation gets no brand from the migration on %s", dbType())

	// The settings row at id 1, written at head through the data layer with no pointer, then
	// carried below 000089.
	require.NoError(t, h.DB.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return h.DB.CreateInitialSettings(ctx, tx, initialSettings("Migration 000089"))
	}))

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeBrands000089), "roll back to 000088 on %s", dbType())
	for _, c := range uiThemes000089 {
		// 1.
		assertNoBrandsTable000089(t, h, "at 000088")
		setUITheme000089(t, h, c.stored)

		// 2.
		require.NoErrorf(t, h.Migrator.Migrate(ctx, brands000089), "apply 000089 on %s", dbType())
		assertBrandsTable000089(t, h, "after apply")
		require.Equalf(t, 1, count000062(t, h, "brands"), "2. one brand for a stored %q on %s", c.stored, dbType())
		def, err := h.DB.GetDefaultBrand(ctx, nil)
		require.NoError(t, err)
		require.NotNilf(t, def, "2. the settings row points at the brand for a stored %q on %s", c.stored, dbType())
		assert.Equalf(t, "Default", def.Name, "2. the brand's name for a stored %q", c.stored)
		assert.Equalf(t, record.BrandAppearance(c.appearance), def.Appearance, "2. a stored %q becomes %q on %s",
			c.stored, c.appearance, dbType())
		assert.Equalf(t, "blueberry", def.Theme, "2. the brand's theme for a stored %q", c.stored)
		assert.Truef(t, def.CreatedAt.Valid && def.UpdatedAt.Valid, "2. the brand's timestamps are stamped on %s", dbType())
		assert.Equalf(t, c.stored, uiThemeOf000089(t, h), "2. ui_theme keeps %q on %s", c.stored, dbType())

		// 6.
		require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeBrands000089), "roll back 000089 on %s", dbType())
		assertNoBrandsTable000089(t, h, "after rolling back")
		assert.Equalf(t, c.writtenBack, uiThemeOf000089(t, h), "6. the down writes %q back for a brand made from %q on %s",
			c.writtenBack, c.stored, dbType())
	}

	// 6. The down writes back the brand's appearance as it is at the down, not the theme the up read.
	setUITheme000089(t, h, "light")
	require.NoErrorf(t, h.Migrator.Migrate(ctx, brands000089), "re-apply 000089 on %s", dbType())
	def, err := h.DB.GetDefaultBrand(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, def)
	def.Appearance = "dark"
	require.NoError(t, h.DB.UpdateBrand(ctx, nil, def))

	// 4.
	other := &record.Brand{Name: "Default", Appearance: "auto", Theme: "plum"}
	require.Errorf(t, h.DB.CreateBrand(ctx, nil, other), "4. a second brand named Default on %s", dbType())
	_, err = h.SQL.Exec(fmt.Sprintf("DELETE FROM brands WHERE id = %d", def.Id))
	require.Errorf(t, err, "4. the foreign key refuses deleting the default brand on %s", dbType())

	// 5.
	_, err = h.SQL.Exec("UPDATE settings SET app_name = 'Previous release', ui_theme = 'light' WHERE id = 1")
	require.NoErrorf(t, err, "save the settings as the previous release does on %s", dbType())
	after, err := h.DB.GetDefaultBrand(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, after, "5. the previous release's save leaves the pointer")
	assert.Equal(t, def.Id, after.Id)
	assert.Equal(t, record.BrandAppearance("dark"), after.Appearance, "5. and the brand")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeBrands000089), "roll back 000089 again on %s", dbType())
	assert.Equalf(t, "dark", uiThemeOf000089(t, h), "6. the down writes back the brand's appearance as edited on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, brands000089), "and apply 000089 once more on %s", dbType())
	assertBrandsTable000089(t, h, "after down/up round trip")
}

// assertBrandsTable000089 holds the declared shape the data layer and the API lean on.
func assertBrandsTable000089(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	brands := dumpTable(t, h, "brands")
	for _, name := range []string{"name", "appearance", "theme"} {
		assert.Falsef(t, brands.column(t, name).Nullable, "[%s] brands.%s is NOT NULL on %s", phase, name, dbType())
	}
	byName := brands.index("idx_brands_name")
	require.Truef(t, byName.Exists, "[%s] the name's unique index on %s; indexes read: %v", phase, dbType(), brands.Indexes)
	assert.Truef(t, byName.Unique, "[%s] a name belongs to one brand on %s", phase, dbType())
	assert.Equalf(t, []string{"name"}, byName.Columns, "[%s] over the name alone on %s", phase, dbType())

	settings := dumpTable(t, h, "settings")
	assert.Truef(t, settings.column(t, "default_brand_id").Nullable,
		"[%s] settings.default_brand_id is nullable, as SQLite needs to add it, on %s", phase, dbType())
	fk := settings.foreignKey(t, "default_brand_id")
	assert.Equalf(t, "brands", fk.RefTable, "[%s] the pointer references brands on %s", phase, dbType())
	assert.Equalf(t, "id", fk.RefColumn, "[%s] by id on %s", phase, dbType())
	_, kept := columnNames000046(settings)["ui_theme"]
	assert.Truef(t, kept, "[%s] ui_theme stays for the previous release on %s", phase, dbType())
}

func assertNoBrandsTable000089(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	assert.NotContainsf(t, listTables(t, h), "brands", "[%s] there is no brands table on %s", phase, dbType())
	_, exists := columnNames000046(dumpTable(t, h, "settings"))["default_brand_id"]
	assert.Falsef(t, exists, "[%s] settings.default_brand_id must not exist on %s", phase, dbType())
}

// setUITheme000089 writes settings row 1's ui_theme with raw SQL, as the previous release stored it.
// The values are ASCII and test-controlled.
func setUITheme000089(t *testing.T, h *isolatedDB, theme string) {
	t.Helper()
	_, err := h.SQL.Exec(fmt.Sprintf("UPDATE settings SET ui_theme = '%s' WHERE id = 1", theme))
	require.NoErrorf(t, err, "store ui_theme %q on %s", theme, dbType())
}

func uiThemeOf000089(t *testing.T, h *isolatedDB) string {
	t.Helper()
	var theme string
	require.NoErrorf(t, h.SQL.QueryRow("SELECT ui_theme FROM settings WHERE id = 1").Scan(&theme),
		"read settings.ui_theme on %s", dbType())
	return theme
}
