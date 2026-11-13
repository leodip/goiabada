package datatests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A brand's custom CSS in storage (#816 decision 4): one text column read and written with the
// brand, '' for none, holding the CSS byte for byte as the admin API passed it.

// sampleCustomCSS is CSS of the kinds an administrator writes, with what a column could mangle:
// quotes, backslash escapes, non-ASCII text, a tab, a form feed and line feeds.
const sampleCustomCSS = "body[data-page=\"sign-in\"] .auth-card {\n" +
	"\tborder: 2px solid var(--color-brand);\n" +
	"}\n" +
	".auth-title::after { content: \"\\2014  Café — 日本語 ✓\"; }\f\n" +
	".auth-logo { background: url('data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22/%3E'); }"

func TestBrand_CustomCSSReadsBackWhatWasWritten(t *testing.T) {
	ctx := context.Background()

	brand := record.NewBrand("Brand "+fake.LetterN(16), "auto", "plum")
	brand.CustomCSS = sampleCustomCSS
	require.NoError(t, database.CreateBrand(ctx, nil, &brand))

	stored, err := database.GetBrandById(ctx, nil, brand.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equalf(t, sampleCustomCSS, stored.CustomCSS, "the CSS byte for byte on %s", dbType())

	all, err := database.GetAllBrands(ctx, nil)
	require.NoError(t, err)
	var listed *record.Brand
	for i := range all {
		if all[i].Id == brand.Id {
			listed = &all[i]
		}
	}
	require.NotNil(t, listed, "the brand is listed")
	assert.Equal(t, sampleCustomCSS, listed.CustomCSS, "the list reads the CSS as the single read does")

	// The most the admin API stores, 65,536 bytes of UTF-8, here three-byte characters inside a
	// comment, fits the column on every engine.
	largest := "/*" + strings.Repeat("✓", (65536-4)/3) + "*/"
	require.Len(t, largest, 65536)
	edit := *stored
	edit.CustomCSS = largest
	require.NoError(t, database.UpdateBrand(ctx, nil, &edit))
	updated, err := database.GetBrandById(ctx, nil, brand.Id)
	require.NoError(t, err)
	require.NotNil(t, updated)
	assert.Equalf(t, largest, updated.CustomCSS, "64 KB of CSS reads back whole on %s", dbType())

	// And a save with none leaves the brand with none.
	edit = *updated
	edit.CustomCSS = ""
	require.NoError(t, database.UpdateBrand(ctx, nil, &edit))
	cleared, err := database.GetBrandById(ctx, nil, brand.Id)
	require.NoError(t, err)
	require.NotNil(t, cleared)
	assert.Empty(t, cleared.CustomCSS, "a brand saved with no CSS reads with none")
	assert.Equal(t, "plum", cleared.Theme)
}

// A brand with no custom CSS stores ”, the value migration 000094 gives every existing brand, and
// not NULL.
func TestBrand_NoCustomCSSIsStoredAsEmpty(t *testing.T) {
	ctx := context.Background()
	h := migratedIsolatedDB(t)

	brand := record.NewBrand("No CSS", "auto", "blueberry")
	require.NoError(t, h.DB.CreateBrand(ctx, nil, &brand))

	var empty int
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
		"SELECT COUNT(*) FROM brands WHERE id = %d AND custom_css = ''", brand.Id)).Scan(&empty))
	assert.Equalf(t, 1, empty, "a brand with no custom CSS stores '' on %s", dbType())
}

// The brand a client's pages are drawn in and the default brand read the CSS as the brand's own
// read does.
func TestBrand_TheDefaultAndAClientsPageBrandReadTheCustomCSS(t *testing.T) {
	ctx := context.Background()
	h, def := brandsIsolatedDB(t)

	def.CustomCSS = ".auth-card { border-width: 3px; }"
	require.NoError(t, h.DB.UpdateBrand(ctx, nil, def))

	byDefault, err := h.DB.GetDefaultBrand(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, byDefault)
	assert.Equal(t, ".auth-card { border-width: 3px; }", byDefault.CustomCSS)

	following := createIsolatedClient(t, h)
	drawnIn, err := h.DB.GetClientPageBrand(ctx, nil, following.ClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, drawnIn)
	assert.Equal(t, def.Id, drawnIn.Id)
	assert.Equal(t, ".auth-card { border-width: 3px; }", drawnIn.CustomCSS)

	own := record.NewBrand("Own", "light", "plum")
	own.CustomCSS = ".auth-title { letter-spacing: 0.05em; }"
	require.NoError(t, h.DB.CreateBrand(ctx, nil, &own))
	given := createIsolatedClient(t, h)
	setBrand(t, h, given.Id, brandId(own.Id))
	drawnIn, err = h.DB.GetClientPageBrand(ctx, nil, given.ClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, drawnIn)
	assert.Equal(t, own.Id, drawnIn.Id)
	assert.Equal(t, ".auth-title { letter-spacing: 0.05em; }", drawnIn.CustomCSS)
}
