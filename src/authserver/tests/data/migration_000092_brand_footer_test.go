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

// The two versions migration 000092 sits between. Literals: nothing in production code names this
// number.
const (
	beforeBrandFooter000092 = 91
	brandFooter000092       = 92
)

// brandFooterColumns000092 are the four columns 000092 adds to brands: the support contact's three
// values and the footer links, the whole list as JSON text (#814 decision 8).
var brandFooterColumns000092 = []string{"support_email", "support_url", "support_phone", "footer_links"}

// TestMigration000092_BrandFooter exercises the migration that stores a brand's footer links and
// support contact (#814 decision 8), against a real engine of the configured dialect.
//
//  1. At 000091 brands has none of the four columns.
//  2. Once 000092 has run, brands gains support_email, support_url, support_phone and
//     footer_links, each required with a default, and nothing else of brands moves.
//  3. Every brand that predates the migration has an empty contact and no links: each contact
//     value is the empty string and footer_links holds the empty list, [], which the data layer
//     reads as no links. Its name, appearance and theme are kept.
//  4. A new installation, migrated with no brand, has the same shape.
//  5. The down migration restores brands to exactly the shape 000091 built, keeping every brand,
//     also one whose contact and links were filled; 000092 applies again after it, and the brand
//     comes back empty.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000092_BrandFooter
func TestMigration000092_BrandFooter(t *testing.T) {
	ctx := context.Background()
	h := migratedIsolatedDB(t)

	// 4.
	assertBrandFooterShape000092(t, h, nil, "on a new installation")

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeBrandFooter000092), "roll back to 000091 on %s", dbType())
	// 1.
	before := dumpTable(t, h, "brands")
	assertNoBrandFooter000092(t, h, "at 000091")

	// Brands that predate the columns, inserted in SQL because the data layer at head names them.
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

	require.NoErrorf(t, h.Migrator.Migrate(ctx, brandFooter000092), "apply 000092 on %s", dbType())
	// 2.
	assertBrandFooterShape000092(t, h, &before, "after apply")

	// 3.
	assertEmpty000092 := func(phase string) {
		t.Helper()
		for _, p := range predating {
			var email, url, phone, links string
			require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
				"SELECT support_email, support_url, support_phone, footer_links FROM brands WHERE id = %d", p.id)).
				Scan(&email, &url, &phone, &links))
			assert.Emptyf(t, email, "[%s] 3. %q has no support email on %s", phase, p.name, dbType())
			assert.Emptyf(t, url, "[%s] 3. %q has no support page on %s", phase, p.name, dbType())
			assert.Emptyf(t, phone, "[%s] 3. %q has no support phone on %s", phase, p.name, dbType())
			assert.Equalf(t, "[]", links, "[%s] 3. %q stores the empty list of links on %s", phase, p.name, dbType())
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
			assert.Emptyf(t, brand.SupportEmail, "[%s] 3. %q reads with no support email on %s", phase, p.name, dbType())
			assert.Emptyf(t, brand.SupportURL, "[%s] 3. %q reads with no support page on %s", phase, p.name, dbType())
			assert.Emptyf(t, brand.SupportPhone, "[%s] 3. %q reads with no support phone on %s", phase, p.name, dbType())
			assert.Nilf(t, brand.FooterLinks, "[%s] 3. %q reads with no links on %s", phase, p.name, dbType())
		}
		if downErr := h.Migrator.Migrate(ctx, brandFooter000092); downErr != nil && !errors.Is(downErr, migrator.ErrNoChange) {
			require.NoErrorf(t, downErr, "roll back to 000092 on %s", dbType())
		}
	}
	assertEmpty000092("after apply")

	// 5. With a brand's contact and links filled, so the down drops columns that hold values.
	night := predating[1].id
	_, err := h.SQL.Exec(fmt.Sprintf("UPDATE brands SET support_email = 'help@example.com', "+
		"support_url = 'https://help.example.com', support_phone = '+5511999990000', "+
		`footer_links = '[{"url":"https://example.com/privacy","label":"Privacy"}]' WHERE id = %d`, night))
	require.NoErrorf(t, err, "fill a brand's contact and links on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeBrandFooter000092), "roll back 000092 on %s", dbType())
	assert.Equalf(t, before, dumpTable(t, h, "brands"),
		"5. 000092's down must restore brands to the shape 000091 built on %s", dbType())
	assertNoBrandFooter000092(t, h, "after rolling back")
	assert.Equalf(t, len(predating), count000062(t, h, "brands"), "5. the down keeps every brand on %s", dbType())

	require.NoErrorf(t, h.Migrator.Migrate(ctx, brandFooter000092), "re-apply 000092 on %s", dbType())
	assertBrandFooterShape000092(t, h, &before, "after a down/up round trip")
	assertEmpty000092("after a down/up round trip")
}

// assertBrandFooterShape000092 holds the four columns to the shape 000092 declares. With before,
// it also holds brands to that shape plus the four columns, and nothing else.
func assertBrandFooterShape000092(t *testing.T, h *isolatedDB, before *tableShape, phase string) {
	t.Helper()
	brands := dumpTable(t, h, "brands")
	for _, name := range brandFooterColumns000092 {
		column := brands.column(t, name)
		assert.Falsef(t, column.Nullable, "[%s] brands.%s is NOT NULL on %s", phase, name, dbType())
		assert.Truef(t, column.HasDefault, "[%s] brands.%s has the default existing brands take on %s", phase, name, dbType())
	}

	if before == nil {
		return
	}
	withoutAdded := brands
	withoutAdded.Columns = slices.DeleteFunc(slices.Clone(brands.Columns),
		func(c schemadump.ColumnShape) bool { return slices.Contains(brandFooterColumns000092, c.Name) })
	assert.Equalf(t, *before, withoutAdded,
		"[%s] 000092 must add the four columns and touch nothing else of brands on %s", phase, dbType())
}

func assertNoBrandFooter000092(t *testing.T, h *isolatedDB, phase string) {
	t.Helper()
	columns := columnNames000046(dumpTable(t, h, "brands"))
	for _, name := range brandFooterColumns000092 {
		_, exists := columns[name]
		assert.Falsef(t, exists, "[%s] brands.%s must not exist on %s", phase, name, dbType())
	}
}
