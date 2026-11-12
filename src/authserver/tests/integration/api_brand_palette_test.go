package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A brand's custom palette through the admin API on a real engine (#815 decisions 1, 2, 5 and 8):
// a basic and an advanced palette created, stored, read, listed and written back unchanged, colors
// and contrastWarnings on every answer, a built-in theme saved over a custom one dropping the
// palette, the refusals with the member error_field points at, and the two audit events.
//
// The colors and failing pairs are the probe's (vectors.json, computed by its JavaScript before any
// Go existed): "a mid-gray brand color" in light, and Blueberry's dark mode rebuilt from its own
// four colors.

// paletteMidGrayLight is the mid-gray vector's light mode, all 23 colors.
var paletteMidGrayLight = map[string]string{"canvas": "#f4f4f4", "surface": "#ffffff", "subtle": "#eeedeb", "line": "#dcdad4",
	"line-strong": "#7d796c", "ink": "#222222", "ink-muted": "#605e5a", "brand": "#777777", "brand-strong": "#606060",
	"on-brand": "#ffffff", "brand-soft": "#ececec", "danger": "#b42318", "danger-strong": "#8f1c13", "on-danger": "#ffffff",
	"danger-soft": "#fdeceb", "danger-ink": "#8f1c13", "positive-soft": "#e3f3e8", "positive-ink": "#17612f",
	"caution-soft": "#fdf2d6", "caution-ink": "#6b4400", "note-soft": "#e6edfb", "note-ink": "#1d4796", "focus": "#777777"}

// paletteBlueberryDark is Blueberry's dark mode worked out from its own four colors.
var paletteBlueberryDark = map[string]string{"canvas": "#0f1217", "surface": "#171b22", "subtle": "#1f242d", "line": "#2e3541",
	"line-strong": "#6e798e", "ink": "#e6e8ec", "ink-muted": "#a4a8b0", "brand": "#8ab4ff", "brand-strong": "#abcaff",
	"on-brand": "#0c1a33", "brand-soft": "#1b2a45", "danger": "#ff8f85", "danger-strong": "#ffb0a8", "on-danger": "#330b07",
	"danger-soft": "#3a1714", "danger-ink": "#ffb4ab", "positive-soft": "#11291a", "positive-ink": "#8fd6a5",
	"caution-soft": "#2e2410", "caution-ink": "#f0c96a", "note-soft": "#142340", "note-ink": "#a8c7ff", "focus": "#8ab4ff"}

// paletteMidGrayWarnings are the mid-gray vector's six failing pairs, in the shared list's order.
var paletteMidGrayWarnings = []any{
	map[string]any{"mode": "light", "foreground": "brand", "background": "canvas", "ratio": 4.07, "minimum": 4.5},
	map[string]any{"mode": "light", "foreground": "brand", "background": "surface", "ratio": 4.47, "minimum": 4.5},
	map[string]any{"mode": "light", "foreground": "on-brand", "background": "brand", "ratio": 4.47, "minimum": 4.5},
	map[string]any{"mode": "light", "foreground": "brand", "background": "subtle", "ratio": 3.82, "minimum": 4.5},
	map[string]any{"mode": "light", "foreground": "brand", "background": "note-soft", "ratio": 3.81, "minimum": 4.5},
	map[string]any{"mode": "light", "foreground": "brand", "background": "caution-soft", "ratio": 4.01, "minimum": 4.5},
}

func paletteJSON(colors map[string]string, tokens ...string) map[string]any {
	object := map[string]any{}
	for token, value := range colors {
		if len(tokens) == 0 || slices.Contains(tokens, token) {
			object[token] = value
		}
	}
	return object
}

// basicTokens are the four colors a basic palette is entered with, for each mode.
var basicTokens = []string{"canvas", "surface", "ink", "brand"}

func TestAPIBrandPalette_BasicAndAdvancedStoredReadListedAndWrittenBack(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	ctx := context.Background()

	for _, c := range []struct {
		mode    record.BrandPaletteMode
		palette map[string]any
		answer  map[string]any
	}{
		{record.BrandPaletteModeBasic,
			// Entered in upper case, answered in lower case.
			map[string]any{"mode": "basic", "light": map[string]any{"canvas": "#F4F4F4", "surface": "#FFFFFF", "ink": "#222222", "brand": "#777777"},
				"dark": paletteJSON(paletteBlueberryDark, basicTokens...)},
			map[string]any{"mode": "basic", "light": paletteJSON(paletteMidGrayLight, basicTokens...),
				"dark": paletteJSON(paletteBlueberryDark, basicTokens...)}},
		{record.BrandPaletteModeAdvanced,
			map[string]any{"mode": "advanced", "light": paletteJSON(paletteMidGrayLight), "dark": paletteJSON(paletteBlueberryDark)},
			map[string]any{"mode": "advanced", "light": paletteJSON(paletteMidGrayLight), "dark": paletteJSON(paletteBlueberryDark)}},
	} {
		t.Run(string(c.mode), func(t *testing.T) {
			name := brandName("Palette")
			status, body, _ := brandCall(t, accessToken, http.MethodPost, brandsPath,
				brandBody(map[string]any{"name": name, "appearance": "auto", "theme": "custom", "palette": c.palette}))
			require.Equal(t, http.StatusCreated, status, "create: %v", body)
			brand := body["brand"].(map[string]any)
			id := int64(brand["id"].(float64))
			*created = append(*created, id)

			assert.Equal(t, "custom", brand["theme"])
			assert.Equal(t, c.answer, brand["palette"])
			assert.Equal(t, map[string]any{"light": paletteJSON(paletteMidGrayLight), "dark": paletteJSON(paletteBlueberryDark)}, brand["colors"])
			assert.Equal(t, paletteMidGrayWarnings, brand["contrastWarnings"])

			stored, err := database.GetBrandById(ctx, nil, id)
			require.NoError(t, err)
			require.NotNil(t, stored)
			assert.Equal(t, "custom", stored.Theme)
			assert.Equal(t, &record.BrandPalette{Mode: c.mode, Light: paletteMidGrayLight, Dark: paletteBlueberryDark}, stored.Palette,
				"the brand stores all 23 colors of each mode")

			status, body, _ = brandCall(t, accessToken, http.MethodGet, brandPath(id, ""), nil)
			require.Equal(t, http.StatusOK, status)
			read := body["brand"].(map[string]any)
			assertBrandReadsAsCreated(t, brand, read)

			status, body, _ = brandCall(t, accessToken, http.MethodGet, brandsPath, nil)
			require.Equal(t, http.StatusOK, status)
			var listed map[string]any
			for _, raw := range body["brands"].([]any) {
				if raw.(map[string]any)["name"] == name {
					listed = raw.(map[string]any)
				}
			}
			require.NotNil(t, listed, "the list holds the brand")
			assert.Equal(t, read["palette"], listed["palette"])
			assert.Equal(t, read["colors"], listed["colors"])
			assert.Equal(t, paletteMidGrayWarnings, listed["contrastWarnings"])

			// Under Dark only the dark mode is checked, which has no failing pair.
			read["appearance"] = "dark"
			status, body, _ = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""), read)
			require.Equal(t, http.StatusOK, status, "write back: %v", body)
			assert.Equal(t, []any{}, body["brand"].(map[string]any)["contrastWarnings"])
			assert.Equal(t, read["palette"], body["brand"].(map[string]any)["palette"])
			rewritten, err := database.GetBrandById(ctx, nil, id)
			require.NoError(t, err)
			assert.Equal(t, stored.Palette, rewritten.Palette, "a palette read and written back is unchanged")

			// A built-in theme saved over the custom one drops the palette.
			status, body, _ = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""),
				brandBody(map[string]any{"name": name, "appearance": "auto", "theme": "tangerine"}))
			require.Equal(t, http.StatusOK, status, "update: %v", body)
			assert.Nil(t, body["brand"].(map[string]any)["palette"])
			assert.Equal(t, "#a84d08", body["brand"].(map[string]any)["colors"].(map[string]any)["light"].(map[string]any)["focus"],
				"a built-in theme answers its own colors")
			assert.Equal(t, []any{}, body["brand"].(map[string]any)["contrastWarnings"])
			dropped, err := database.GetBrandById(ctx, nil, id)
			require.NoError(t, err)
			assert.Equal(t, "tangerine", dropped.Theme)
			assert.Nil(t, dropped.Palette)
		})
	}
}

// The theme custom is not listed among the built-in themes.
func TestAPIBrandPalette_TheCustomThemeIsNotListed(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	status, body, _ := brandCall(t, accessToken, http.MethodGet, brandThemesPath, nil)
	require.Equal(t, http.StatusOK, status)
	for _, raw := range body["brandThemes"].([]any) {
		assert.NotEqual(t, "custom", raw.(map[string]any)["key"])
	}
}

func TestAPIBrandPalette_Refusals(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	other := createBrandOverAPI(t, accessToken, created, brandName("Other"), "auto", "blueberry")

	basic := func(edit func(p map[string]any)) map[string]any {
		p := map[string]any{"mode": "basic", "light": paletteJSON(paletteMidGrayLight, basicTokens...),
			"dark": paletteJSON(paletteBlueberryDark, basicTokens...)}
		edit(p)
		return brandBody(map[string]any{"name": brandName("New"), "appearance": "auto", "theme": "custom", "palette": p})
	}
	refusals := []struct {
		name, code, field, description string
		body                           map[string]any
	}{
		{"custom with no palette", "handler.brand.palette_required", "/palette", "The custom theme needs a palette.",
			brandBody(map[string]any{"name": brandName("New"), "appearance": "auto", "theme": "custom"})},
		{"a built-in theme with a palette", "handler.brand.palette_not_custom", "/palette",
			"A palette can be set only with the custom theme.",
			brandBody(map[string]any{"name": brandName("New"), "appearance": "auto", "theme": "plum",
				"palette": map[string]any{"mode": "basic"}})},
		{"an unknown mode", "handler.brand.palette_mode_invalid", "/palette/mode", "The palette's mode must be basic or advanced.",
			basic(func(p map[string]any) { p["mode"] = "simple" })},
		{"no dark colors", "handler.brand.palette_colors_required", "/palette/dark", "The palette needs its dark colors.",
			basic(func(p map[string]any) { delete(p, "dark") })},
		{"no brand color", "handler.brand.palette_color_required", "/palette/light/brand", "The palette's light colors need a brand color.",
			basic(func(p map[string]any) { delete(p["light"].(map[string]any), "brand") })},
		{"a name that is no token", "handler.brand.palette_color_unknown", "/palette/dark/accent",
			"The palette's dark colors name accent, which is not a color token.",
			basic(func(p map[string]any) { p["dark"].(map[string]any)["accent"] = "#123456" })},
		{"a worked-out color in basic mode", "handler.brand.palette_color_not_basic", "/palette/light/focus",
			"A basic palette sets only canvas, surface, ink and brand, and its light colors name focus.",
			basic(func(p map[string]any) { p["light"].(map[string]any)["focus"] = "#123456" })},
		{"a three-digit color", "handler.brand.palette_color_invalid", "/palette/light/ink",
			"The palette's light ink color must be # and six hexadecimal digits, such as #2456c4.",
			basic(func(p map[string]any) { p["light"].(map[string]any)["ink"] = "#222" })},
	}
	for _, c := range refusals {
		for _, write := range []struct{ method, path string }{{http.MethodPost, brandsPath}, {http.MethodPut, brandPath(other, "")}} {
			t.Run(write.method+" "+c.name, func(t *testing.T) {
				status, body, _ := brandCall(t, accessToken, write.method, write.path, c.body)
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, c.code, body["error_code"])
				assert.Equal(t, c.description, body["error_description"])
				assert.Equal(t, c.field, body["error_field"])
			})
		}
	}

	stored, err := database.GetBrandById(context.Background(), nil, other)
	require.NoError(t, err)
	assert.Equal(t, "blueberry", stored.Theme, "no refused update wrote the brand")
	assert.Nil(t, stored.Palette)
}

// The audit events record the theme custom and the palette's mode, and no color (decision 2).
func TestAPIBrandPalette_ChangesAreAudited(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	who := caller.ClientIdentifier
	_, created := keepDefaultBrand(t)

	name := brandName("AuditPalette")
	resp, requestId := sendAdmin(t, accessToken, http.MethodPost, brandsPath, brandBody(map[string]any{
		"name": name, "appearance": "light", "theme": "custom", "palette": map[string]any{"mode": "basic",
			"light": paletteJSON(paletteMidGrayLight, basicTokens...), "dark": paletteJSON(paletteBlueberryDark, basicTokens...)}}))
	var answer map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", answer)
	id := int64(answer["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, id)
	createdRows := auditRows(t, accessToken, "created_brand", requestId)
	assert.Equal(t, []map[string]any{{"brand_id": float64(id), "brand_name": name, "theme": "custom",
		"palette_mode": "basic", "logged_in_user": who}}, createdRows)

	_, _, requestId = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""),
		brandBody(map[string]any{"name": name, "appearance": "dark", "theme": "custom", "palette": map[string]any{"mode": "advanced",
			"light": paletteJSON(paletteMidGrayLight), "dark": paletteJSON(paletteBlueberryDark)}}))
	updatedRows := auditRows(t, accessToken, "updated_brand", requestId)
	assert.Equal(t, []map[string]any{{"brand_id": float64(id), "brand_name": name, "appearance": "dark",
		"theme": "custom", "palette_mode": "advanced", "corners": "rounded", "font": "system-ui", "background_fit": "cover",
		"hide_app_name": false, "logged_in_user": who}}, updatedRows)

	for _, rows := range [][]map[string]any{createdRows, updatedRows} {
		encoded, err := json.Marshal(rows)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), "#", "no color is recorded")
	}
}
