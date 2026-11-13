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

// The two versions migration 000094 sits between. Literals: nothing in production code names this
// number.
const (
	beforeBrandCustomCSS000094 = 93
	brandCustomCSS000094       = 94
)

// TestMigration000094_BrandCustomCSS exercises the migration that stores a brand's custom CSS
// (#816), against a real engine of the configured dialect.
//
//  1. At 000093 brands has no custom_css column.
//  2. Once 000094 has run, brands gains custom_css, not nullable, with a default, and nothing else
//     of brands moves.
//  3. Every brand that predates the migration has no custom CSS: the column holds ”.
//  4. A new installation, migrated with no brand, has the same shape.
//  5. The down migration restores brands to exactly the shape 000093 built, keeping every brand,
//     also one whose CSS was set; 000094 applies again after it, and the brand comes back with
//     none.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000094_BrandCustomCSS
func TestMigration000094_BrandCustomCSS(t *testing.T) {
	ctx := context.Background()
	h := migratedIsolatedDB(t)

	// 4.
	assertBrandCustomCSSShape000094(t, h, nil, "on a new installation")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeBrandCustomCSS000094), "roll back to 000093 on %s", dbType())
	// 1.
	before := dumpTable(t, h, "brands")
	assertNoBrandCustomCSS000094(t, h, "at 000093")

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

	require.NoErrorf(t, h.Migrator.Migrate(ctx, brandCustomCSS000094), "apply 000094 on %s", dbType())
	// 2.
	assertBrandCustomCSSShape000094(t, h, &before, "after apply")

	// 3.
	assertNoCSS000094 := func(phase string) {
		t.Helper()
		for _, p := range predating {
			var empty int
			require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
				"SELECT COUNT(*) FROM brands WHERE id = %d AND custom_css = ''", p.id)).Scan(&empty))
			assert.Equalf(t, 1, empty, "[%s] 3. %q has no custom CSS on %s", phase, p.name, dbType())
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
			assert.Equalf(t, p.theme, brand.Theme, "[%s] its theme", phase)
			assert.Emptyf(t, brand.CustomCSS, "[%s] 3. %q reads with no custom CSS on %s", phase, p.name, dbType())
		}
		if downErr := h.Migrator.Migrate(ctx, brandCustomCSS000094); downErr != nil && !errors.Is(downErr, migrator.ErrNoChange) {
			require.NoErrorf(t, downErr, "roll back to 000094 on %s", dbType())
		}
	}
	assertNoCSS000094("after apply")

	// 5. With a brand's CSS set, so the down drops a column that holds a value.
	night := predating[1].id
	_, err := h.SQL.Exec(fmt.Sprintf(`UPDATE brands SET custom_css = '.auth-card { border-width: 3px; }' WHERE id = %d`, night))
	require.NoErrorf(t, err, "set a brand's custom CSS on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeBrandCustomCSS000094), "roll back 000094 on %s", dbType())
	assert.Equalf(t, before, dumpTable(t, h, "brands"),
		"5. 000094's down must restore brands to the shape 000093 built on %s", dbType())
	assertNoBrandCustomCSS000094(t, h, "after rolling back")
	assert.Equalf(t, len(predating), count000062(t, h, "brands"), "5. the down keeps every brand on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, brandCustomCSS000094), "re-apply 000094 on %s", dbType())
	assertBrandCustomCSSShape000094(t, h, &before, "after a down/up round trip")
	assertNoCSS000094("after a down/up round trip")
}

// assertBrandCustomCSSShape000094 holds the custom_css column to the shape 000094 declares. With
// before, it also holds brands to that shape plus the column, and nothing else.
func assertBrandCustomCSSShape000094(t *testing.T, h *isolatedDB, before *tableShape, phase string) {
	t.Helper()
	brands := dumpTable(t, h, "brands")
	column := brands.column(t, "custom_css")
	assert.Falsef(t, column.Nullable, "[%s] brands.custom_css is not nullable, '' for none, on %s", phase, dbType())
	assert.Truef(t, column.HasDefault, "[%s] brands.custom_css has a default, '', on %s", phase, dbType())

	if before == nil {
		return
	}
	withoutAdded := brands
	withoutAdded.Columns = slices.DeleteFunc(slices.Clone(brands.Columns),
		func(c schemadump.ColumnShape) bool { return c.Name == "custom_css" })
	assert.Equalf(t, *before, withoutAdded,
		"[%s] 000094 must add the custom_css column and touch nothing else of brands on %s", phase, dbType())
}

func assertNoBrandCustomCSS000094(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	_, exists := columnNames000046(dumpTable(t, h, "brands"))["custom_css"]
	assert.Falsef(t, exists, "[%s] brands.custom_css must not exist on %s", phase, dbType())
}
