package datatests

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/schemadump"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000093 sits between. Literals: nothing in production code names this
// number.
const (
	beforeBrandPalette000093 = 92
	brandPalette000093       = 93
)

// TestMigration000093_BrandPalette exercises the migration that stores a brand's custom palette
// (#815 decision 3), against a real engine of the configured dialect.
//
//  1. At 000092 brands has no palette column.
//  2. Once 000093 has run, brands gains palette, nullable and with no default, and nothing else of
//     brands moves.
//  3. Every brand that predates the migration keeps its built-in theme and has no palette: the
//     column is NULL, which the data layer reads as no palette.
//  4. A new installation, migrated with no brand, has the same shape.
//  5. The down migration restores brands to exactly the shape 000092 built, keeping every brand,
//     also one whose palette was set; 000093 applies again after it, and the brand comes back with
//     none.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000093_BrandPalette
func TestMigration000093_BrandPalette(t *testing.T) {
	ctx := context.Background()
	h := migratedIsolatedDB(t)

	// 4.
	assertBrandPaletteShape000093(t, h, nil, "on a new installation")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeBrandPalette000093), "roll back to 000092 on %s", dbType())
	// 1.
	before := dumpTable(t, h, "brands")
	assertNoBrandPalette000093(t, h, "at 000092")

	// Brands that predate the column, inserted in SQL because the data layer at head names it.
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

	require.NoErrorf(t, h.Migrator.Migrate(ctx, brandPalette000093), "apply 000093 on %s", dbType())
	// 2.
	assertBrandPaletteShape000093(t, h, &before, "after apply")

	// 3.
	assertNoPalette000093 := func(phase string) {
		t.Helper()
		for _, p := range predating {
			var nulls int
			require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
				"SELECT COUNT(*) FROM brands WHERE id = %d AND palette IS NULL", p.id)).Scan(&nulls))
			assert.Equalf(t, 1, nulls, "[%s] 3. %q has a NULL palette on %s", phase, p.name, dbType())
		}

		// The data layer's brand reads name the columns of later migrations, so these are read at head.
		if upErr := h.Migrator.Up(ctx); upErr != nil && !errors.Is(upErr, migrator.ErrNoChange) {
			require.NoErrorf(t, upErr, "migrate to head on %s", dbType())
		}
		for _, p := range predating {
			brand, err := h.DB.GetBrandById(ctx, nil, p.id)
			require.NoError(t, err)
			require.NotNilf(t, brand, "[%s] the brand %q is kept on %s", phase, p.name, dbType())
			assert.Equalf(t, p.name, brand.Name, "[%s] its name", phase)
			assert.Equalf(t, p.theme, brand.Theme, "[%s] 3. %q keeps its built-in theme", phase, p.name)
			assert.Nilf(t, brand.Palette, "[%s] 3. %q reads with no palette on %s", phase, p.name, dbType())
		}
		if downErr := h.Migrator.Migrate(ctx, brandPalette000093); downErr != nil && !errors.Is(downErr, migrator.ErrNoChange) {
			require.NoErrorf(t, downErr, "roll back to 000093 on %s", dbType())
		}
	}
	assertNoPalette000093("after apply")

	// 5. With a brand's palette set, so the down drops a column that holds a value.
	night := predating[1].id
	_, err := h.SQL.Exec(fmt.Sprintf(`UPDATE brands SET theme = 'custom', palette = '{"mode":"basic"}' WHERE id = %d`, night))
	require.NoErrorf(t, err, "set a brand's palette on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeBrandPalette000093), "roll back 000093 on %s", dbType())
	assert.Equalf(t, before, dumpTable(t, h, "brands"),
		"5. 000093's down must restore brands to the shape 000092 built on %s", dbType())
	assertNoBrandPalette000093(t, h, "after rolling back")
	assert.Equalf(t, len(predating), count000062(t, h, "brands"), "5. the down keeps every brand on %s", dbType())

	// The down leaves the theme as it was; put it back so the brand reads as it predated 000093.
	_, err = h.SQL.Exec(fmt.Sprintf("UPDATE brands SET theme = 'plum' WHERE id = %d", night))
	require.NoError(t, err)
	require.NoErrorf(t, h.Migrator.Migrate(ctx, brandPalette000093), "re-apply 000093 on %s", dbType())
	assertBrandPaletteShape000093(t, h, &before, "after a down/up round trip")
	assertNoPalette000093("after a down/up round trip")
}

// assertBrandPaletteShape000093 holds the palette column to the shape 000093 declares. With before,
// it also holds brands to that shape plus the column, and nothing else.
func assertBrandPaletteShape000093(t *testing.T, h *isolatedDB, before *tableShape, phase string) {
	t.Helper()
	brands := dumpTable(t, h, "brands")
	column := brands.column(t, "palette")
	assert.Truef(t, column.Nullable, "[%s] brands.palette is nullable, NULL for a built-in theme, on %s", phase, dbType())
	assert.Falsef(t, column.HasDefault, "[%s] brands.palette has no default on %s", phase, dbType())

	if before == nil {
		return
	}
	withoutAdded := brands
	withoutAdded.Columns = slices.DeleteFunc(slices.Clone(brands.Columns),
		func(c schemadump.ColumnShape) bool { return c.Name == "palette" })
	assert.Equalf(t, *before, withoutAdded,
		"[%s] 000093 must add the palette column and touch nothing else of brands on %s", phase, dbType())
}

func assertNoBrandPalette000093(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	_, exists := columnNames000046(dumpTable(t, h, "brands"))["palette"]
	assert.Falsef(t, exists, "[%s] brands.palette must not exist on %s", phase, dbType())
}
