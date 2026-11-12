package apihandlers

import (
	"database/sql"
	"log/slog"
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A brand's custom palette in the admin API (#815 decisions 1, 2, 5 and 8), one rule per case,
// through the create, update and read handlers with the generated database mock: the theme custom
// and its palette member, each refusal with the member error_field points at, the 23 colors of
// each mode worked out at the save and stored, the colors and contrastWarnings every answer carries
// for the modes the appearance draws, a brand read and sent back unchanged, and the audit events.
//
// The expected colors and failing pairs are the probe's (vectors.json, computed by its JavaScript
// before any Go existed): "a mid-gray brand color", "a navy card with white text on a pale
// background", and the Blueberry theme's dark mode rebuilt from its own four colors.

// midGrayLight is the mid-gray vector's light mode, all 23 colors: its four entered colors, the
// eight it works out, and Blueberry's light status colors, since its text is darker than its card.
var midGrayLight = map[string]string{"canvas": "#f4f4f4", "surface": "#ffffff", "subtle": "#eeedeb", "line": "#dcdad4",
	"line-strong": "#7d796c", "ink": "#222222", "ink-muted": "#605e5a", "brand": "#777777", "brand-strong": "#606060",
	"on-brand": "#ffffff", "brand-soft": "#ececec", "danger": "#b42318", "danger-strong": "#8f1c13", "on-danger": "#ffffff",
	"danger-soft": "#fdeceb", "danger-ink": "#8f1c13", "positive-soft": "#e3f3e8", "positive-ink": "#17612f",
	"caution-soft": "#fdf2d6", "caution-ink": "#6b4400", "note-soft": "#e6edfb", "note-ink": "#1d4796", "focus": "#777777"}

// midGrayWarnings are the mid-gray vector's six failing pairs, in the shared list's order.
var midGrayWarnings = []any{
	warning("light", "brand", "canvas", 4.07, 4.5),
	warning("light", "brand", "surface", 4.47, 4.5),
	warning("light", "on-brand", "brand", 4.47, 4.5),
	warning("light", "brand", "subtle", 3.82, 4.5),
	warning("light", "brand", "note-soft", 3.81, 4.5),
	warning("light", "brand", "caution-soft", 4.01, 4.5),
}

// blueberryDarkRebuilt is Blueberry's dark mode worked out from its own four colors, which has no
// failing pair, with Blueberry's dark status colors.
var blueberryDarkRebuilt = map[string]string{"canvas": "#0f1217", "surface": "#171b22", "subtle": "#1f242d", "line": "#2e3541",
	"line-strong": "#6e798e", "ink": "#e6e8ec", "ink-muted": "#a4a8b0", "brand": "#8ab4ff", "brand-strong": "#abcaff",
	"on-brand": "#0c1a33", "brand-soft": "#1b2a45", "danger": "#ff8f85", "danger-strong": "#ffb0a8", "on-danger": "#330b07",
	"danger-soft": "#3a1714", "danger-ink": "#ffb4ab", "positive-soft": "#11291a", "positive-ink": "#8fd6a5",
	"caution-soft": "#2e2410", "caution-ink": "#f0c96a", "note-soft": "#142340", "note-ink": "#a8c7ff", "focus": "#8ab4ff"}

// navyCard is the navy-card vector's 23 colors: a white text on a navy card over a pale background,
// with Blueberry's dark status colors, since its text is lighter than its card.
var navyCard = map[string]string{"canvas": "#eef1f6", "surface": "#1f3a68", "subtle": "#fdfeff", "line": "#ffffff",
	"line-strong": "#7c8596", "ink": "#ffffff", "ink-muted": "#ffffff", "brand": "#ffd166", "brand-strong": "#fffefd",
	"on-brand": "#241900", "brand-soft": "#5a4a28", "danger": "#ff8f85", "danger-strong": "#ffb0a8", "on-danger": "#330b07",
	"danger-soft": "#3a1714", "danger-ink": "#ffb4ab", "positive-soft": "#11291a", "positive-ink": "#8fd6a5",
	"caution-soft": "#2e2410", "caution-ink": "#f0c96a", "note-soft": "#142340", "note-ink": "#a8c7ff", "focus": "#fffefd"}

// navyCardWarnings are the navy-card vector's ten failing pairs, in the shared list's order, as a
// dark mode's.
var navyCardWarnings = []any{
	warning("dark", "ink", "canvas", 1.13, 4.5),
	warning("dark", "ink", "subtle", 1, 4.5),
	warning("dark", "ink-muted", "canvas", 1.13, 4.5),
	warning("dark", "ink-muted", "subtle", 1, 4.5),
	warning("dark", "brand", "canvas", 1.27, 4.5),
	warning("dark", "danger-ink", "canvas", 1.49, 4.5),
	warning("dark", "brand", "subtle", 1.42, 4.5),
	warning("dark", "brand-strong", "subtle", 1, 4.5),
	warning("dark", "focus", "canvas", 1.12, 3),
	warning("dark", "focus", "subtle", 1, 3),
}

// warning is one item of contrastWarnings as the JSON answer decodes it.
func warning(mode, foreground, background string, ratio, minimum float64) map[string]any {
	return map[string]any{"mode": mode, "foreground": foreground, "background": background,
		"ratio": ratio, "minimum": minimum}
}

// basicOf is the four entered colors of a mode, out of its 23.
func basicOf(colors map[string]string) map[string]string {
	return map[string]string{"canvas": colors["canvas"], "surface": colors["surface"], "ink": colors["ink"], "brand": colors["brand"]}
}

// asJSON is a color map as a request body or a decoded answer holds it.
func asJSON(colors map[string]string) map[string]any {
	object := map[string]any{}
	for token, value := range colors {
		object[token] = value
	}
	return object
}

// upper is a color map with every value in upper case, which a write accepts.
func upper(colors map[string]string) map[string]any {
	object := map[string]any{}
	for token, value := range colors {
		object[token] = strings.ToUpper(value)
	}
	return object
}

// customBody is a valid brand body on the custom theme with the given palette.
func customBody(appearance string, palette map[string]any) map[string]any {
	body := validBrandBody()
	body["appearance"] = appearance
	body["theme"] = "custom"
	body["palette"] = palette
	return body
}

// basicPalette is the mid-gray light mode and Blueberry's dark mode as a basic palette.
func basicPalette() map[string]any {
	return map[string]any{"mode": "basic", "light": asJSON(basicOf(midGrayLight)), "dark": asJSON(basicOf(blueberryDarkRebuilt))}
}

// advancedPalette is the mid-gray light mode and the navy card as the dark mode, all 23 colors set.
func advancedPalette() map[string]any {
	return map[string]any{"mode": "advanced", "light": asJSON(midGrayLight), "dark": asJSON(navyCard)}
}

// paletteEdit is a valid custom body whose palette edit changed.
func paletteEdit(palette func() map[string]any, edit func(p map[string]any)) map[string]any {
	p := palette()
	edit(p)
	return customBody("auto", p)
}

func modeOf(p map[string]any, mode string) map[string]any { return p[mode].(map[string]any) }

// brandPaletteRefusals are the refusals of decision 2, each decided on the request alone, and the
// member error_field points at.
var brandPaletteRefusals = []struct {
	name  string
	body  map[string]any
	code  string
	field string
}{
	{"the custom theme with no palette", func() map[string]any { b := customBody("auto", nil); delete(b, "palette"); return b }(),
		"handler.brand.palette_required", "/palette"},
	{"the custom theme with a null palette", customBody("auto", nil), "handler.brand.palette_required", "/palette"},
	{"a built-in theme with a palette", func() map[string]any { b := validBrandBody(); b["palette"] = basicPalette(); return b }(),
		"handler.brand.palette_not_custom", "/palette"},
	{"a built-in theme with an empty palette", func() map[string]any { b := validBrandBody(); b["palette"] = map[string]any{}; return b }(),
		"handler.brand.palette_not_custom", "/palette"},

	{"no mode", paletteEdit(basicPalette, func(p map[string]any) { delete(p, "mode") }), "handler.brand.palette_mode_invalid", "/palette/mode"},
	{"a mode in capitals", paletteEdit(basicPalette, func(p map[string]any) { p["mode"] = "Basic" }), "handler.brand.palette_mode_invalid", "/palette/mode"},
	{"an unknown mode", paletteEdit(basicPalette, func(p map[string]any) { p["mode"] = "simple" }), "handler.brand.palette_mode_invalid", "/palette/mode"},

	// Both modes are always sent, whatever the appearance.
	{"no light colors", paletteEdit(basicPalette, func(p map[string]any) { delete(p, "light") }), "handler.brand.palette_colors_required", "/palette/light"},
	{"null dark colors", paletteEdit(advancedPalette, func(p map[string]any) { p["dark"] = nil }), "handler.brand.palette_colors_required", "/palette/dark"},

	{"a basic mode with no brand color", paletteEdit(basicPalette, func(p map[string]any) { delete(modeOf(p, "light"), "brand") }),
		"handler.brand.palette_color_required", "/palette/light/brand"},
	{"an advanced mode with no focus color", paletteEdit(advancedPalette, func(p map[string]any) { delete(modeOf(p, "dark"), "focus") }),
		"handler.brand.palette_color_required", "/palette/dark/focus"},
	{"an advanced palette with four colors a mode", paletteEdit(advancedPalette, func(p map[string]any) { p["light"] = asJSON(basicOf(midGrayLight)) }),
		"handler.brand.palette_color_required", "/palette/light/subtle"},
	{"a name that is no token", paletteEdit(advancedPalette, func(p map[string]any) { modeOf(p, "light")["accent"] = "#123456" }),
		"handler.brand.palette_color_unknown", "/palette/light/accent"},
	{"a token's name with its CSS prefix", paletteEdit(basicPalette, func(p map[string]any) { modeOf(p, "dark")["--color-brand"] = "#123456" }),
		"handler.brand.palette_color_unknown", "/palette/dark/--color-brand"},
	// RFC 6901 section 3: "~" is written "~0" and "/" is written "~1" in a reference token.
	{"a name holding a slash and a tilde", paletteEdit(basicPalette, func(p map[string]any) { modeOf(p, "light")["a/b~c"] = "#123456" }),
		"handler.brand.palette_color_unknown", "/palette/light/a~1b~0c"},
	{"a basic mode naming a worked-out color", paletteEdit(basicPalette, func(p map[string]any) { modeOf(p, "dark")["subtle"] = "#123456" }),
		"handler.brand.palette_color_not_basic", "/palette/dark/subtle"},
	{"a basic palette sending all 23", paletteEdit(basicPalette, func(p map[string]any) { p["light"] = asJSON(midGrayLight) }),
		"handler.brand.palette_color_not_basic", "/palette/light/brand-soft"},

	{"a three-digit color", paletteEdit(basicPalette, func(p map[string]any) { modeOf(p, "light")["brand"] = "#777" }),
		"handler.brand.palette_color_invalid", "/palette/light/brand"},
	{"a color name", paletteEdit(basicPalette, func(p map[string]any) { modeOf(p, "dark")["ink"] = "white" }),
		"handler.brand.palette_color_invalid", "/palette/dark/ink"},
	{"eight digits", paletteEdit(advancedPalette, func(p map[string]any) { modeOf(p, "dark")["note-ink"] = "#a8c7ffcc" }),
		"handler.brand.palette_color_invalid", "/palette/dark/note-ink"},
	{"no #", paletteEdit(basicPalette, func(p map[string]any) { modeOf(p, "light")["canvas"] = "f4f4f4" }),
		"handler.brand.palette_color_invalid", "/palette/light/canvas"},
	{"a digit that is not hexadecimal", paletteEdit(basicPalette, func(p map[string]any) { modeOf(p, "light")["surface"] = "#fffffg" }),
		"handler.brand.palette_color_invalid", "/palette/light/surface"},
	{"surrounding spaces", paletteEdit(basicPalette, func(p map[string]any) { modeOf(p, "light")["surface"] = " #ffffff" }),
		"handler.brand.palette_color_invalid", "/palette/light/surface"},
	{"an empty color", paletteEdit(advancedPalette, func(p map[string]any) { modeOf(p, "light")["focus"] = "" }),
		"handler.brand.palette_color_invalid", "/palette/light/focus"},
}

func TestBrandPalette_CreateRefusals(t *testing.T) {
	for _, c := range brandPaletteRefusals {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)

			status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
				brandRequest(t, http.MethodPost, c.body))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(answer))
			assertErrorField(t, c.field, answer)
			database.AssertNotCalled(t, "CreateBrand", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestBrandPalette_UpdateRefusals(t *testing.T) {
	for _, c := range brandPaletteRefusals {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
				Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()

			status, answer := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
				brandRequest(t, http.MethodPut, c.body, "id", "3"))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(answer))
			assertErrorField(t, c.field, answer)
			database.AssertNotCalled(t, "UpdateBrand", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// The sentences name the mode and the token as the request spells them.
func TestBrandPalette_TheSentenceNamesTheModeAndTheToken(t *testing.T) {
	database := datamocks.NewDatabase(t)

	_, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
		brandRequest(t, http.MethodPost, paletteEdit(basicPalette, func(p map[string]any) { modeOf(p, "dark")["ink"] = "white" })))

	assert.Equal(t, "The palette's dark ink color must be # and six hexadecimal digits, such as #2456c4.", answer["error_description"])
}

// A basic palette is worked out when it is saved: the brand stores all 23 colors of each mode, the
// four entered in lower case and the 19 worked out, and answers palette as it was written, its four
// colors a mode, colors as stored, and the failing pairs of both modes under auto (decisions 1, 2
// and 5).
func TestBrandPalette_ABasicPaletteIsWorkedOutWhenSaved(t *testing.T) {
	database := datamocks.NewDatabase(t)
	var stored record.Brand
	expectCreate(database, &stored)
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()
	palette := map[string]any{"mode": "basic", "light": upper(basicOf(midGrayLight)), "dark": upper(basicOf(blueberryDarkRebuilt))}

	status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL),
		brandRequest(t, http.MethodPost, customBody("auto", palette)))

	require.Equal(t, http.StatusCreated, status, "%v", answer)
	assert.Equal(t, "custom", stored.Theme)
	assert.Equal(t, &record.BrandPalette{Mode: record.BrandPaletteModeBasic, Light: midGrayLight, Dark: blueberryDarkRebuilt}, stored.Palette)
	assert.Equal(t, "custom", brandAt(answer, "brand", "theme"))
	assert.Equal(t, map[string]any{"mode": "basic", "light": asJSON(basicOf(midGrayLight)), "dark": asJSON(basicOf(blueberryDarkRebuilt))},
		brandAt(answer, "brand", "palette"), "palette answers what was written, in lower case")
	assert.Equal(t, map[string]any{"light": asJSON(midGrayLight), "dark": asJSON(blueberryDarkRebuilt)}, brandAt(answer, "brand", "colors"))
	assert.Equal(t, midGrayWarnings, brandAt(answer, "brand", "contrastWarnings"))
}

// An advanced palette is stored as it was entered, in lower case, and answered whole in palette and
// in colors.
func TestBrandPalette_AnAdvancedPaletteIsStoredAsEntered(t *testing.T) {
	database := datamocks.NewDatabase(t)
	var stored record.Brand
	expectCreate(database, &stored)
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()
	palette := map[string]any{"mode": "advanced", "light": upper(midGrayLight), "dark": asJSON(navyCard)}

	status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL),
		brandRequest(t, http.MethodPost, customBody("auto", palette)))

	require.Equal(t, http.StatusCreated, status, "%v", answer)
	assert.Equal(t, &record.BrandPalette{Mode: record.BrandPaletteModeAdvanced, Light: midGrayLight, Dark: navyCard}, stored.Palette)
	assert.Equal(t, advancedPalette(), brandAt(answer, "brand", "palette"))
	assert.Equal(t, map[string]any{"light": asJSON(midGrayLight), "dark": asJSON(navyCard)}, brandAt(answer, "brand", "colors"))
}

// storedCustomBrand is brand 5 on the custom theme, the mid-gray light mode and the navy card dark
// mode set in advanced mode.
func storedCustomBrand(appearance record.BrandAppearance) *record.Brand {
	brand := storedBrand(5, "Acme", appearance, "custom")
	brand.Palette = &record.BrandPalette{Mode: record.BrandPaletteModeAdvanced, Light: maps.Clone(midGrayLight), Dark: maps.Clone(navyCard)}
	return brand
}

// expectBrandRead is what a brand read needs besides the brand: the default and the counts.
func expectBrandRead(database *datamocks.Database, brand *record.Brand) {
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), brand.Id).Return(brand, nil).Once()
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
	database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()
}

// contrastWarnings holds the failing pairs of the modes the appearance draws, light before dark,
// each in the shared list's order (decisions 5 and 8); colors holds both modes whatever the
// appearance.
func TestBrandPalette_TheWarningsAreThoseOfTheModesTheAppearanceDraws(t *testing.T) {
	for _, c := range []struct {
		appearance record.BrandAppearance
		want       []any
	}{
		{record.BrandAppearanceAuto, append(append([]any{}, midGrayWarnings...), navyCardWarnings...)},
		{record.BrandAppearanceLight, midGrayWarnings},
		{record.BrandAppearanceDark, navyCardWarnings},
	} {
		t.Run(string(c.appearance), func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			expectBrandRead(database, storedCustomBrand(c.appearance))

			status, answer := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "5"))

			require.Equal(t, http.StatusOK, status)
			assert.Equal(t, c.want, brandAt(answer, "brand", "contrastWarnings"))
			assert.Equal(t, map[string]any{"light": asJSON(midGrayLight), "dark": asJSON(navyCard)}, brandAt(answer, "brand", "colors"))
		})
	}
}

// A palette with no failing pair answers [], and so does a built-in theme, by the same code; a
// built-in theme answers its own colors and a null palette.
func TestBrandPalette_NoFailingPairAndABuiltInTheme(t *testing.T) {
	t.Run("a custom palette with no failing pair", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		brand := storedBrand(5, "Acme", record.BrandAppearanceDark, "custom")
		brand.Palette = &record.BrandPalette{Mode: record.BrandPaletteModeBasic, Light: maps.Clone(midGrayLight), Dark: maps.Clone(blueberryDarkRebuilt)}
		expectBrandRead(database, brand)

		status, answer := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "5"))

		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, []any{}, brandAt(answer, "brand", "contrastWarnings"))
	})
	for _, theme := range []string{"plum", "high-contrast"} {
		t.Run(theme, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			expectBrandRead(database, storedBrand(3, "Acme", record.BrandAppearanceAuto, theme))

			status, answer := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "3"))

			require.Equal(t, http.StatusOK, status)
			assert.Nil(t, brandAt(answer, "brand", "palette"))
			assert.Contains(t, answer["brand"], "palette", "palette is answered as null")
			assert.Equal(t, []any{}, brandAt(answer, "brand", "contrastWarnings"))
			light, _ := brandAt(answer, "brand", "colors", "light").(map[string]any)
			dark, _ := brandAt(answer, "brand", "colors", "dark").(map[string]any)
			assert.Len(t, light, 23)
			assert.Len(t, dark, 23)
		})
	}
	t.Run("plum's own colors", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		expectBrandRead(database, storedBrand(3, "Acme", record.BrandAppearanceAuto, "plum"))

		_, answer := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "3"))

		assert.Equal(t, "#f6f4f7", brandAt(answer, "brand", "colors", "light", "canvas"))
		assert.Equal(t, "#5a5163", brandAt(answer, "brand", "colors", "light", "ink-muted"))
	})
}

// A custom brand with no palette can only come from a hand edit of the database: it is logged, and
// its palette and colors answer null, with no warnings (decision 3).
func TestBrandPalette_ACustomBrandWithNoPaletteAnswersNull(t *testing.T) {
	capture := logtest.CaptureSlog(t)
	database := datamocks.NewDatabase(t)
	expectBrandRead(database, storedBrand(5, "Acme", record.BrandAppearanceAuto, "custom"))

	status, answer := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "5"))

	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, answer["brand"], "palette")
	assert.Nil(t, brandAt(answer, "brand", "palette"))
	assert.Contains(t, answer["brand"], "colors")
	assert.Nil(t, brandAt(answer, "brand", "colors"))
	assert.Equal(t, []any{}, brandAt(answer, "brand", "contrastWarnings"))
	records := capture.Records()
	require.Len(t, records, 1)
	assert.Equal(t, slog.LevelWarn, records[0].Level)
	assert.Equal(t, "brand has the custom theme and no palette", records[0].Message)
	assert.EqualValues(t, 5, records[0].Attrs["brand_id"])
}

// The list answers each brand's colors and warnings too.
func TestBrandPalette_TheListAnswersColorsAndWarnings(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetAllBrands", mock.Anything, (*sql.Tx)(nil)).Return([]record.Brand{
		*storedCustomBrand(record.BrandAppearanceLight), *storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"),
	}, nil).Once()
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
	database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()

	status, answer := serveBrand(HandleBrandsGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil))

	require.Equal(t, http.StatusOK, status)
	brands := answer["brands"].([]any)
	require.Len(t, brands, 2)
	assert.Equal(t, "Acme", brandAt(brands[0], "name"))
	assert.Equal(t, midGrayWarnings, brandAt(brands[0], "contrastWarnings"))
	assert.Equal(t, advancedPalette(), brandAt(brands[0], "palette"))
	assert.Equal(t, []any{}, brandAt(brands[1], "contrastWarnings"))
	assert.Equal(t, "#2456c4", brandAt(brands[1], "colors", "light", "brand"))
}

// A custom brand read and sent back is the same brand: palette is answered exactly as it is
// written, and colors and contrastWarnings are read-only, ignored on a write as id is (decision 2).
// A basic palette saved again is worked out again from its four colors, to the same 23.
func TestBrandPalette_ACustomBrandReadAndWrittenBackIsUnchanged(t *testing.T) {
	for _, mode := range []record.BrandPaletteMode{record.BrandPaletteModeBasic, record.BrandPaletteModeAdvanced} {
		t.Run(string(mode), func(t *testing.T) {
			stored := func() *record.Brand {
				brand := storedBrand(5, "Acme", record.BrandAppearanceAuto, "custom")
				brand.Palette = &record.BrandPalette{Mode: mode, Light: maps.Clone(midGrayLight), Dark: maps.Clone(blueberryDarkRebuilt)}
				return brand
			}
			database := datamocks.NewDatabase(t)
			database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(stored(), nil).Once()
			database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(stored(), nil).Once()
			database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
				Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Twice()
			database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Twice()
			var written record.Brand
			database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
				written = *args.Get(2).(*record.Brand)
			}).Return(nil).Once()
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, mock.Anything).Once()

			status, read := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "5"))
			require.Equal(t, http.StatusOK, status)
			status, again := serveBrand(HandleBrandUpdatePut(database, auditLogger, brandBaseURL),
				brandRequest(t, http.MethodPut, read["brand"], "id", "5"))

			require.Equal(t, http.StatusOK, status, "%v", again)
			assert.Equal(t, *stored(), written)
			assert.Equal(t, read["brand"], again["brand"])
		})
	}
}

// Saving a built-in theme over a custom one drops the stored palette, the palette left out or null
// (decision 2).
func TestBrandPalette_ABuiltInThemeSavedOverACustomOneDropsThePalette(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(body map[string]any)
	}{
		{"palette left out", func(body map[string]any) {}},
		{"palette null", func(body map[string]any) { body["palette"] = nil }},
	} {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(storedCustomBrand(record.BrandAppearanceAuto), nil).Once()
			database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
				Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
			database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()
			var written record.Brand
			database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
				written = *args.Get(2).(*record.Brand)
			}).Return(nil).Once()
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, mock.Anything).Once()
			body := validBrandBody()
			c.edit(body)

			status, answer := serveBrand(HandleBrandUpdatePut(database, auditLogger, brandBaseURL),
				brandRequest(t, http.MethodPut, body, "id", "5"))

			require.Equal(t, http.StatusOK, status, "%v", answer)
			assert.Equal(t, "plum", written.Theme)
			assert.Nil(t, written.Palette)
			assert.Nil(t, brandAt(answer, "brand", "palette"))
		})
	}
}

// The audit events record the theme custom and the palette's mode, and no color (decision 2).
func TestBrandPalette_TheAuditEventsRecordTheThemeAndTheMode(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		var stored record.Brand
		expectCreate(database, &stored)
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, map[string]interface{}{
			"brand_id": int64(7), "brand_name": "Acme", "theme": "custom", "palette_mode": "basic",
			"logged_in_user": brandCaller,
		}).Once()

		status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL),
			brandRequest(t, http.MethodPost, customBody("dark", basicPalette())))

		require.Equal(t, http.StatusCreated, status, "%v", answer)
	})
	t.Run("update", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
			Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()
		database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(nil).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
		database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, map[string]interface{}{
			"brand_id": int64(3), "brand_name": "Acme", "appearance": "light", "theme": "custom",
			"palette_mode": "advanced", "corners": "pill", "font": "serif", "background_fit": "contain",
			"hide_app_name": false, "logged_in_user": brandCaller,
		}).Once()

		status, answer := serveBrand(HandleBrandUpdatePut(database, auditLogger, brandBaseURL),
			brandRequest(t, http.MethodPut, customBody("light", advancedPalette()), "id", "3"))

		require.Equal(t, http.StatusOK, status, "%v", answer)
	})
}
