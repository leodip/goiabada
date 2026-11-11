package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000091 sits between. Literals: nothing in production code names this
// number.
const (
	beforeBrandKit000091 = 90
	brandKit000091       = 91
)

// brandKitChoices000091 are the four columns 000091 adds to brands for a brand's choices.
var brandKitChoices000091 = []string{"corners", "font", "background_fit", "hide_app_name"}

// brandKitSlots000091 are the six slot columns 000091 adds to brands, each with its index.
var brandKitSlots000091 = []string{
	"logo_asset_id", "dark_logo_asset_id", "favicon_asset_id",
	"background_asset_id", "regular_font_asset_id", "bold_font_asset_id",
}

// TestMigration000091_BrandKit exercises the migration that stores the brand kit (#813 decision 2),
// against a real engine of the configured dialect.
//
//  1. At 000090 there is no brand_assets table and brands has none of the kit's columns.
//  2. Once 000091 has run, brand_assets holds each asset's kind, content type, fingerprint, pixel
//     size, bytes and creation time, all required, with an index over the creation time for the
//     sweep; brands gains the four choices, required, and six nullable slots, each a foreign key
//     to brand_assets(id) with no cascade and an index of its own, and nothing else of brands
//     moves.
//  3. Every brand that predates the kit is drawn as it was: rounded, System UI, cover, the app
//     name shown, every slot empty. Its name, appearance and theme are kept.
//  4. A new installation, migrated with no brand, has the same shape and no asset.
//  5. The foreign keys refuse deleting an asset a slot names, and a slot naming no asset.
//  6. The down migration restores brands to exactly the shape 000090 built, keeping every brand,
//     and drops brand_assets; 000091 applies again after it.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000091_BrandKit
func TestMigration000091_BrandKit(t *testing.T) {
	ctx := context.Background()
	h := migratedIsolatedDB(t)

	// 4.
	assertBrandKitShape000091(t, h, nil, "on a new installation")
	assert.Equalf(t, 0, count000062(t, h, "brand_assets"), "4. a new installation has no asset on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeBrandKit000091), "roll back to 000090 on %s", dbType())
	// 1.
	before := dumpTable(t, h, "brands")
	assertNoBrandKit000091(t, h, "at 000090")

	// Brands that predate the kit, inserted in SQL because the data layer at head names its columns.
	predating := []struct {
		name, appearance, theme string
		id                      int64
	}{
		{name: "Default", appearance: "auto", theme: "blueberry"},
		{name: "Night", appearance: "dark", theme: "plum"},
	}
	for i := range predating {
		predating[i].id = insertBrand000091(t, h, predating[i].name, predating[i].appearance, predating[i].theme)
	}

	require.NoErrorf(t, h.Migrator.Migrate(ctx, brandKit000091), "apply 000091 on %s", dbType())
	// 2.
	assertBrandKitShape000091(t, h, &before, "after apply")

	// 3.
	assertDrawnAsBefore000091 := func(phase string) {
		t.Helper()
		for _, p := range predating {
			brand, err := h.DB.GetBrandById(ctx, nil, p.id)
			require.NoError(t, err)
			require.NotNilf(t, brand, "[%s] the brand %q is kept on %s", phase, p.name, dbType())
			assert.Equalf(t, p.name, brand.Name, "[%s] its name", phase)
			assert.Equalf(t, record.BrandAppearance(p.appearance), brand.Appearance, "[%s] its appearance", phase)
			assert.Equalf(t, p.theme, brand.Theme, "[%s] its theme", phase)
			assert.Equalf(t, record.BrandCorners("rounded"), brand.Corners, "[%s] 3. %q is rounded on %s", phase, p.name, dbType())
			assert.Equalf(t, record.BrandFont("system-ui"), brand.Font, "[%s] 3. %q is on System UI on %s", phase, p.name, dbType())
			assert.Equalf(t, record.BrandBackgroundFit("cover"), brand.BackgroundFit, "[%s] 3. %q fits cover on %s", phase, p.name, dbType())
			assert.Falsef(t, brand.HideAppName, "[%s] 3. %q shows the app name on %s", phase, p.name, dbType())
			for _, s := range []sql.NullInt64{brand.LogoAssetId, brand.DarkLogoAssetId, brand.FaviconAssetId,
				brand.BackgroundAssetId, brand.RegularFontAssetId, brand.BoldFontAssetId} {
				assert.Equalf(t, sql.NullInt64{}, s, "[%s] 3. every slot of %q is empty on %s", phase, p.name, dbType())
			}
		}
	}
	assertDrawnAsBefore000091("after apply")

	// 5.
	logo := createTestBrandAsset(t, h.DB, record.BrandAssetKindLogo)
	night := predating[1].id
	for _, column := range brandKitSlots000091 {
		_, err := h.SQL.Exec(fmt.Sprintf("UPDATE brands SET %s = %d WHERE id = %d", column, logo.Id, night))
		require.NoErrorf(t, err, "5. a slot %s naming a stored asset on %s", column, dbType())
		_, err = h.SQL.Exec(fmt.Sprintf("DELETE FROM brand_assets WHERE id = %d", logo.Id))
		require.Errorf(t, err, "5. the foreign key on %s refuses deleting the asset it names on %s", column, dbType())
		_, err = h.SQL.Exec(fmt.Sprintf("UPDATE brands SET %s = NULL WHERE id = %d", column, night))
		require.NoError(t, err)

		_, err = h.SQL.Exec(fmt.Sprintf("UPDATE brands SET %s = %d WHERE id = %d", column, logo.Id+1_000, night))
		require.Errorf(t, err, "5. the foreign key on %s refuses a slot naming no asset on %s", column, dbType())
	}

	// 6. With a slot filled, so the down drops a column that holds a value.
	_, err := h.SQL.Exec(fmt.Sprintf("UPDATE brands SET logo_asset_id = %d WHERE id = %d", logo.Id, night))
	require.NoError(t, err)
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeBrandKit000091), "roll back 000091 on %s", dbType())
	assert.Equalf(t, before, dumpTable(t, h, "brands"),
		"6. 000091's down must restore brands to the shape 000090 built on %s", dbType())
	assertNoBrandKit000091(t, h, "after rolling back")
	assert.Equalf(t, len(predating), count000062(t, h, "brands"), "6. the down keeps every brand on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, brandKit000091), "re-apply 000091 on %s", dbType())
	assertBrandKitShape000091(t, h, &before, "after a down/up round trip")
	assertDrawnAsBefore000091("after a down/up round trip")
}

// insertBrand000091 writes a brand as 000090 stores it and answers its id. The values are ASCII
// and test-controlled.
func insertBrand000091(t *testing.T, h *isolatedDB, name, appearance, theme string) int64 {
	t.Helper()
	_, err := h.SQL.Exec(fmt.Sprintf("INSERT INTO brands (name, appearance, theme) VALUES ('%s', '%s', '%s')",
		name, appearance, theme))
	require.NoErrorf(t, err, "insert the brand %q at 000090 on %s", name, dbType())
	var id int64
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf("SELECT id FROM brands WHERE name = '%s'", name)).Scan(&id))
	return id
}

// assertBrandKitShape000091 holds brand_assets and brands to the shape 000091 declares. With
// before, it also holds brands to that shape plus the added columns, their foreign keys and their
// indexes, and nothing else.
func assertBrandKitShape000091(t *testing.T, h *isolatedDB, before *tableShape, phase string) {
	t.Helper()
	assets := dumpTable(t, h, "brand_assets")
	for _, name := range []string{"created_at", "kind", "content_type", "fingerprint", "width", "height", "content"} {
		assert.Falsef(t, assets.column(t, name).Nullable, "[%s] brand_assets.%s is NOT NULL on %s", phase, name, dbType())
	}
	_, hasUpdatedAt := columnNames000046(assets)["updated_at"]
	assert.Falsef(t, hasUpdatedAt, "[%s] an asset never changes, so it has no updated_at, on %s", phase, dbType())
	byCreation := assets.index("idx_brand_assets_created_at")
	require.Truef(t, byCreation.Exists, "[%s] the sweep's index on %s; indexes read: %v", phase, dbType(), assets.Indexes)
	assert.Equalf(t, []string{"created_at"}, byCreation.Columns, "[%s] over created_at alone on %s", phase, dbType())

	brands := dumpTable(t, h, "brands")
	for _, name := range brandKitChoices000091 {
		column := brands.column(t, name)
		assert.Falsef(t, column.Nullable, "[%s] brands.%s is NOT NULL on %s", phase, name, dbType())
		assert.Truef(t, column.HasDefault, "[%s] brands.%s has the default existing brands take on %s", phase, name, dbType())
	}
	assetId := assets.column(t, "id")
	for _, name := range brandKitSlots000091 {
		column := brands.column(t, name)
		assert.Truef(t, column.Nullable, "[%s] brands.%s is nullable: NULL is an empty slot, on %s", phase, name, dbType())
		assert.Falsef(t, column.HasDefault, "[%s] brands.%s has no default on %s", phase, name, dbType())
		assert.Equalf(t, assetId.Type, column.Type, "[%s] brands.%s has brand_assets.id's type on %s", phase, name, dbType())

		fk := brands.foreignKey(t, name)
		assert.Equalf(t, "brand_assets", fk.RefTable, "[%s] brands.%s references brand_assets on %s", phase, name, dbType())
		assert.Equalf(t, "id", fk.RefColumn, "[%s] by id on %s", phase, dbType())
		assert.Containsf(t, []string{"NO ACTION", "RESTRICT"}, fk.OnDelete,
			"[%s] brands.%s has no cascade: only the sweep deletes an asset, and never one a slot names, on %s",
			phase, name, dbType())

		index := brands.index("idx_brands_" + name)
		require.Truef(t, index.Exists, "[%s] the index over brands.%s on %s; indexes read: %v", phase, name, dbType(), brands.Indexes)
		assert.Falsef(t, index.Unique, "[%s] brands may share an asset on %s", phase, dbType())
		assert.Equalf(t, []string{name}, index.Columns, "[%s] over %s alone on %s", phase, name, dbType())
	}

	if before == nil {
		return
	}
	added := append(slices.Clone(brandKitChoices000091), brandKitSlots000091...)
	withoutAdded := brands
	withoutAdded.Columns = slices.DeleteFunc(slices.Clone(brands.Columns),
		func(c schemadump.ColumnShape) bool { return slices.Contains(added, c.Name) })
	withoutAdded.Indexes = slices.DeleteFunc(slices.Clone(brands.Indexes),
		func(i schemadump.IndexShape) bool {
			return slices.ContainsFunc(brandKitSlots000091, func(s string) bool { return i.Name == "idx_brands_"+s })
		})
	withoutAdded.ForeignKeys = slices.DeleteFunc(slices.Clone(brands.ForeignKeys),
		func(f schemadump.ForeignKeyShape) bool { return slices.Contains(brandKitSlots000091, f.Column) })
	if len(withoutAdded.ForeignKeys) == 0 && before.ForeignKeys == nil {
		// brands had no foreign key before, which the dump reads as none at all.
		withoutAdded.ForeignKeys = nil
	}
	assert.Equalf(t, *before, withoutAdded,
		"[%s] 000091 must add the kit's columns, foreign keys and indexes and touch nothing else of brands on %s",
		phase, dbType())
}

func assertNoBrandKit000091(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	assert.NotContainsf(t, listTables(t, h), "brand_assets", "[%s] there is no brand_assets table on %s", phase, dbType())
	columns := columnNames000046(dumpTable(t, h, "brands"))
	for _, name := range append(slices.Clone(brandKitChoices000091), brandKitSlots000091...) {
		_, exists := columns[name]
		assert.Falsef(t, exists, "[%s] brands.%s must not exist on %s", phase, name, dbType())
	}
}
