package datatests

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A brand's custom palette in storage (#815 decision 3): one nullable column holding the palette
// whole as JSON text, the mode and the 23 colors of each of the two modes, read and written with
// the brand, and NULL for a brand on a built-in theme.

// paletteUnparsedMessage is the warning a read logs for a stored palette it cannot use.
const paletteUnparsedMessage = "brand palette does not parse and is read as none"

// lightColors and darkColors are a full mode each, written out: Blueberry's own colors, with the
// light brand colors replaced by an orange so no value is the built-in theme's by accident.
func lightColors() map[string]string {
	return map[string]string{
		"canvas": "#f6f7f9", "surface": "#ffffff", "subtle": "#eef1f5", "line": "#d5dbe3",
		"line-strong": "#6c7686", "ink": "#151a22", "ink-muted": "#525b6b",
		"brand": "#b54708", "brand-strong": "#93370d", "on-brand": "#ffffff", "brand-soft": "#fef0e7",
		"danger": "#b42318", "danger-strong": "#8f1c13", "on-danger": "#ffffff", "danger-soft": "#fdeceb",
		"danger-ink": "#8f1c13", "positive-soft": "#e3f3e8", "positive-ink": "#17612f",
		"caution-soft": "#fdf2d6", "caution-ink": "#6b4400", "note-soft": "#e6edfb", "note-ink": "#1d4796",
		"focus": "#b54708",
	}
}

func darkColors() map[string]string {
	return map[string]string{
		"canvas": "#0f1217", "surface": "#171b22", "subtle": "#1f242d", "line": "#2f3541",
		"line-strong": "#6f7889", "ink": "#e6e8ec", "ink-muted": "#a0a8b6",
		"brand": "#f79009", "brand-strong": "#fdb022", "on-brand": "#1f1300", "brand-soft": "#3a2410",
		"danger": "#ff8f85", "danger-strong": "#ffb0a8", "on-danger": "#330b07", "danger-soft": "#3a1714",
		"danger-ink": "#ffb4ab", "positive-soft": "#11291a", "positive-ink": "#8fd6a5",
		"caution-soft": "#2e2410", "caution-ink": "#f0c96a", "note-soft": "#142340", "note-ink": "#a8c7ff",
		"focus": "#f79009",
	}
}

func TestBrand_APaletteReadsBackWhatWasWritten(t *testing.T) {
	ctx := context.Background()

	basic := &record.BrandPalette{Mode: record.BrandPaletteModeBasic, Light: lightColors(), Dark: darkColors()}
	brand := record.NewBrand("Brand "+fake.LetterN(16), "auto", "custom")
	brand.Palette = basic
	require.NoError(t, database.CreateBrand(ctx, nil, &brand))

	stored, err := database.GetBrandById(ctx, nil, brand.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "custom", stored.Theme)
	assert.Equal(t, &record.BrandPalette{Mode: "basic", Light: lightColors(), Dark: darkColors()}, stored.Palette,
		"the mode and the 46 colors, as written")

	all, err := database.GetAllBrands(ctx, nil)
	require.NoError(t, err)
	var listed *record.Brand
	for i := range all {
		if all[i].Id == brand.Id {
			listed = &all[i]
		}
	}
	require.NotNil(t, listed, "the brand is listed")
	assert.Equal(t, &record.BrandPalette{Mode: "basic", Light: lightColors(), Dark: darkColors()}, listed.Palette,
		"the list reads the palette as the single read does")

	// An update writes the palette whole: advanced now, with a color typed in upper case, which is a
	// color and is stored as it was written.
	light := lightColors()
	light["ink-muted"] = "#4A5363"
	dark := darkColors()
	dark["focus"] = "#ffffff"
	edit := *stored
	edit.Palette = &record.BrandPalette{Mode: record.BrandPaletteModeAdvanced, Light: light, Dark: dark}
	require.NoError(t, database.UpdateBrand(ctx, nil, &edit))

	updated, err := database.GetBrandById(ctx, nil, brand.Id)
	require.NoError(t, err)
	require.NotNil(t, updated)
	wantLight := lightColors()
	wantLight["ink-muted"] = "#4A5363"
	wantDark := darkColors()
	wantDark["focus"] = "#ffffff"
	assert.Equal(t, &record.BrandPalette{Mode: "advanced", Light: wantLight, Dark: wantDark}, updated.Palette)

	// And a built-in theme saved over it leaves the brand with no palette.
	edit = *updated
	edit.Theme = "plum"
	edit.Palette = nil
	require.NoError(t, database.UpdateBrand(ctx, nil, &edit))
	cleared, err := database.GetBrandById(ctx, nil, brand.Id)
	require.NoError(t, err)
	require.NotNil(t, cleared)
	assert.Nil(t, cleared.Palette, "a brand saved with no palette reads with none")
	assert.Equal(t, "plum", cleared.Theme)
}

// The brand a client's pages are drawn in and the default brand read the palette as the brand's
// own read does.
func TestBrand_TheDefaultAndAClientsPageBrandReadThePalette(t *testing.T) {
	ctx := context.Background()
	h, def := brandsIsolatedDB(t)

	def.Theme = "custom"
	def.Palette = &record.BrandPalette{Mode: record.BrandPaletteModeAdvanced, Light: lightColors(), Dark: darkColors()}
	require.NoError(t, h.DB.UpdateBrand(ctx, nil, def))

	byDefault, err := h.DB.GetDefaultBrand(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, byDefault)
	assert.Equal(t, &record.BrandPalette{Mode: "advanced", Light: lightColors(), Dark: darkColors()}, byDefault.Palette)

	following := createIsolatedClient(t, h)
	drawnIn, err := h.DB.GetClientPageBrand(ctx, nil, following.ClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, drawnIn)
	assert.Equal(t, def.Id, drawnIn.Id)
	assert.Equal(t, &record.BrandPalette{Mode: "advanced", Light: lightColors(), Dark: darkColors()}, drawnIn.Palette)

	// A client given a brand of its own reads that brand's palette.
	own := record.NewBrand("Own", "light", "custom")
	own.Palette = &record.BrandPalette{Mode: record.BrandPaletteModeBasic, Light: darkColors(), Dark: lightColors()}
	require.NoError(t, h.DB.CreateBrand(ctx, nil, &own))
	given := createIsolatedClient(t, h)
	setBrand(t, h, given.Id, brandId(own.Id))
	drawnIn, err = h.DB.GetClientPageBrand(ctx, nil, given.ClientIdentifier)
	require.NoError(t, err)
	require.NotNil(t, drawnIn)
	assert.Equal(t, own.Id, drawnIn.Id)
	assert.Equal(t, &record.BrandPalette{Mode: "basic", Light: darkColors(), Dark: lightColors()}, drawnIn.Palette)
}

// A brand with no palette stores NULL, the value migration 000093 gives every existing brand, and
// not some other spelling of nothing.
func TestBrand_NoPaletteIsStoredAsNull(t *testing.T) {
	ctx := context.Background()
	h := migratedIsolatedDB(t)

	brand := record.NewBrand("No palette", "auto", "blueberry")
	require.NoError(t, h.DB.CreateBrand(ctx, nil, &brand))

	isNull := func(phase string) {
		t.Helper()
		var nulls int
		require.NoError(t, h.SQL.QueryRow(fmt.Sprintf(
			"SELECT COUNT(*) FROM brands WHERE id = %d AND palette IS NULL", brand.Id)).Scan(&nulls))
		assert.Equalf(t, 1, nulls, "[%s] a brand with no palette stores NULL on %s", phase, dbType())
	}
	isNull("create")

	brand.Theme = "custom"
	brand.Palette = &record.BrandPalette{Mode: record.BrandPaletteModeBasic, Light: lightColors(), Dark: darkColors()}
	require.NoError(t, h.DB.UpdateBrand(ctx, nil, &brand))
	var stored string
	require.NoError(t, h.SQL.QueryRow(fmt.Sprintf("SELECT palette FROM brands WHERE id = %d", brand.Id)).Scan(&stored))
	var asJSON map[string]any
	require.NoErrorf(t, json.Unmarshal([]byte(stored), &asJSON), "the stored palette is JSON text on %s", dbType())
	assert.Equal(t, "basic", asJSON["mode"])

	brand.Theme = "blueberry"
	brand.Palette = nil
	require.NoError(t, h.DB.UpdateBrand(ctx, nil, &brand))
	isNull("update")
}

// A write never stores a palette a read would refuse: the data layer refuses it, and the brand is
// not written.
func TestBrand_APaletteThatIsNotCompleteOrNotColorsIsNotWritten(t *testing.T) {
	ctx := context.Background()

	missing := lightColors()
	delete(missing, "focus")
	notAColor := darkColors()
	notAColor["ink"] = "#fff"
	for name, palette := range map[string]*record.BrandPalette{
		"a mode lacking a color":  {Mode: record.BrandPaletteModeAdvanced, Light: missing, Dark: darkColors()},
		"a value that is not one": {Mode: record.BrandPaletteModeAdvanced, Light: lightColors(), Dark: notAColor},
		"no mode":                 {Light: lightColors(), Dark: darkColors()},
	} {
		brand := record.NewBrand("Brand "+fake.LetterN(16), "auto", "custom")
		brand.Palette = palette
		require.Errorf(t, database.CreateBrand(ctx, nil, &brand), "%s is refused on %s", name, dbType())

		valid := record.NewBrand("Brand "+fake.LetterN(16), "auto", "blueberry")
		require.NoError(t, database.CreateBrand(ctx, nil, &valid))
		valid.Palette = palette
		require.Errorf(t, database.UpdateBrand(ctx, nil, &valid), "%s is refused on update on %s", name, dbType())
		stored, err := database.GetBrandById(ctx, nil, valid.Id)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.Nilf(t, stored.Palette, "%s: the brand keeps no palette on %s", name, dbType())
	}
}

// storedPalette is a palette's text as a hand edit of the database could leave it: members to
// marshal, each a value or a mode's map.
func storedPalette(t *testing.T, members map[string]any) string {
	t.Helper()
	text, err := json.Marshal(members)
	require.NoError(t, err)
	return string(text)
}

// withColor is a mode with one token set to value, or removed when value is nil.
func withColor(mode map[string]string, token string, value any) map[string]any {
	out := map[string]any{}
	for k, v := range mode {
		out[k] = v
	}
	if value == nil {
		delete(out, token)
	} else {
		out[token] = value
	}
	return out
}

// The engine cannot check the text's shape, so a stored value that is not a complete palette of
// colors reads as no palette, logged, and the brand is still read: only a complete palette of
// #rrggbb values ever reaches a stylesheet (#815 decision 3).
func TestBrand_AStoredPaletteThatDoesNotParseReadsAsNone(t *testing.T) {
	ctx := context.Background()
	h, def := brandsIsolatedDB(t)
	_, setupErr := h.SQL.Exec(fmt.Sprintf("UPDATE brands SET theme = 'custom', support_email = 'help@example.com' WHERE id = %d", def.Id))
	require.NoError(t, setupErr)

	light, dark := lightColors(), darkColors()
	whole := func(mode any, l, d any) map[string]any {
		return map[string]any{"mode": mode, "light": l, "dark": d}
	}
	tooMany := maps.Clone(light)
	tooMany["shadow"] = "#000000"

	for name, stored := range map[string]string{
		"not JSON":                    "not json",
		"empty text":                  "",
		"JSON null":                   "null",
		"a list":                      "[]",
		"cut short":                   storedPalette(t, whole("basic", light, dark))[:40],
		"text after the object":       storedPalette(t, whole("basic", light, dark)) + " {}",
		"no mode":                     storedPalette(t, map[string]any{"light": light, "dark": dark}),
		"an unknown mode":             storedPalette(t, whole("simple", light, dark)),
		"a mode in upper case":        storedPalette(t, whole("BASIC", light, dark)),
		"a mode that is a number":     storedPalette(t, whole(1, light, dark)),
		"no light":                    storedPalette(t, map[string]any{"mode": "basic", "dark": dark}),
		"no dark":                     storedPalette(t, map[string]any{"mode": "basic", "light": light}),
		"a null dark":                 storedPalette(t, whole("basic", light, nil)),
		"light as a list":             storedPalette(t, whole("basic", []string{"#ffffff"}, dark)),
		"an unknown member":           storedPalette(t, map[string]any{"mode": "basic", "light": light, "dark": dark, "version": 2}),
		"light lacking a color":       storedPalette(t, whole("advanced", withColor(light, "focus", nil), dark)),
		"dark lacking a color":        storedPalette(t, whole("advanced", light, withColor(dark, "canvas", nil))),
		"only the four basic colors":  storedPalette(t, whole("basic", map[string]string{"canvas": "#ffffff", "surface": "#ffffff", "ink": "#000000", "brand": "#2456c4"}, dark)),
		"a token that is not one":     storedPalette(t, whole("advanced", tooMany, dark)),
		"three digits":                storedPalette(t, whole("advanced", withColor(light, "ink", "#000"), dark)),
		"a color name":                storedPalette(t, whole("advanced", withColor(light, "ink", "black"), dark)),
		"eight digits":                storedPalette(t, whole("advanced", light, withColor(dark, "brand", "#f79009ff"))),
		"no #":                        storedPalette(t, whole("advanced", light, withColor(dark, "brand", "f79009"))),
		"not hexadecimal":             storedPalette(t, whole("advanced", light, withColor(dark, "brand", "#f7900g"))),
		"a value that is a number":    storedPalette(t, whole("advanced", light, withColor(dark, "brand", 123456))),
		"an empty value":              storedPalette(t, whole("advanced", withColor(light, "on-brand", ""), dark)),
		"a value with a CSS fragment": storedPalette(t, whole("advanced", withColor(light, "brand", "#000000;}body{"), dark)),
	} {
		_, err := h.SQL.Exec(fmt.Sprintf("UPDATE brands SET palette = '%s' WHERE id = %d", stored, def.Id))
		require.NoErrorf(t, err, "%s: store %q on %s", name, stored, dbType())

		capture := logtest.CaptureSlog(t)

		byId, err := h.DB.GetBrandById(ctx, nil, def.Id)
		require.NoErrorf(t, err, "%s: the brand is still read on %s", name, dbType())
		require.NotNil(t, byId)
		assert.Nilf(t, byId.Palette, "%s reads as no palette on %s", name, dbType())
		assert.Equalf(t, "help@example.com", byId.SupportEmail, "%s: the rest of the brand is read on %s", name, dbType())
		assert.Equal(t, "custom", byId.Theme, "the theme is read as stored")

		byDefault, err := h.DB.GetDefaultBrand(ctx, nil)
		require.NoErrorf(t, err, "%s: the default brand is still read on %s", name, dbType())
		require.NotNil(t, byDefault)
		assert.Nilf(t, byDefault.Palette, "%s reads as no palette on %s", name, dbType())

		all, err := h.DB.GetAllBrands(ctx, nil)
		require.NoErrorf(t, err, "%s: the list is still read on %s", name, dbType())
		require.Len(t, all, 1)
		assert.Nilf(t, all[0].Palette, "%s reads as no palette on %s", name, dbType())

		var logged []logtest.CapturedRecord
		for _, r := range capture.Records() {
			if r.Message == paletteUnparsedMessage {
				logged = append(logged, r)
			}
		}
		require.Lenf(t, logged, 3, "%s: each of the three reads logs it on %s", name, dbType())
		for _, r := range logged {
			assert.Equal(t, slog.LevelWarn, r.Level)
			assert.Equal(t, def.Id, r.Attrs["brand_id"], "the record names the brand")
			assert.NotEmpty(t, r.Attrs["error"], "the record carries why")
		}
	}

	// A complete palette reads as itself again, and logs nothing; so does NULL, as no palette.
	_, err := h.SQL.Exec(fmt.Sprintf("UPDATE brands SET palette = '%s' WHERE id = %d",
		storedPalette(t, whole("basic", light, dark)), def.Id))
	require.NoError(t, err)
	capture := logtest.CaptureSlog(t)
	byId, err := h.DB.GetBrandById(ctx, nil, def.Id)
	require.NoError(t, err)
	require.NotNil(t, byId)
	assert.Equal(t, &record.BrandPalette{Mode: "basic", Light: lightColors(), Dark: darkColors()}, byId.Palette)

	_, err = h.SQL.Exec(fmt.Sprintf("UPDATE brands SET palette = NULL WHERE id = %d", def.Id))
	require.NoError(t, err)
	byId, err = h.DB.GetBrandById(ctx, nil, def.Id)
	require.NoError(t, err)
	require.NotNil(t, byId)
	assert.Nil(t, byId.Palette)
	for _, r := range capture.Records() {
		assert.NotEqual(t, paletteUnparsedMessage, r.Message)
	}
}
