package render

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// paletteBrand is a brand of id 9 on the custom theme, with a whole stored palette written out by
// hand around a yellow brand color, all 23 colors of each mode.
func paletteBrand(appearance record.BrandAppearance) *record.Brand {
	light := map[string]string{"canvas": "#fafaf7", "surface": "#ffffff", "subtle": "#f4f4f0", "line": "#e1e1d9",
		"line-strong": "#7f7f6f", "ink": "#1c1c18", "ink-muted": "#5a5a4f", "brand": "#f5c400", "brand-strong": "#7a5f00",
		"on-brand": "#000000", "brand-soft": "#fdf3d8", "danger": "#b42318", "danger-strong": "#8f1c13", "on-danger": "#ffffff",
		"danger-soft": "#fdeceb", "danger-ink": "#8f1c13", "positive-soft": "#e3f3e8", "positive-ink": "#17612f",
		"caution-soft": "#fdf2d6", "caution-ink": "#6b4400", "note-soft": "#e6edfb", "note-ink": "#1d4796", "focus": "#8a6c00"}
	dark := map[string]string{"canvas": "#121210", "surface": "#1a1a17", "subtle": "#22221e", "line": "#33332d",
		"line-strong": "#7d7d6d", "ink": "#ecece6", "ink-muted": "#ababa0", "brand": "#f5c400", "brand-strong": "#ffd84d",
		"on-brand": "#000000", "brand-soft": "#2d2610", "danger": "#ff8f85", "danger-strong": "#ffb0a8", "on-danger": "#330b07",
		"danger-soft": "#3a1714", "danger-ink": "#ffb4ab", "positive-soft": "#11291a", "positive-ink": "#8fd6a5",
		"caution-soft": "#2e2410", "caution-ink": "#f0c96a", "note-soft": "#142340", "note-ink": "#a8c7ff", "focus": "#f5c400"}
	brand := record.NewBrand("Sunny", appearance, record.BrandThemeCustom)
	brand.Id = 9
	brand.Palette = &record.BrandPalette{Mode: record.BrandPaletteModeAdvanced, Light: light, Dark: dark}
	return &brand
}

func renderNotFound(t *testing.T, brands *defaultBrandStub) pageHead {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test"}))
	buf, err := New(web.TemplateFS(), web.StaticFS(), brands).RenderTemplateToBuffer(req,
		"/layouts/no_menu_layout.html", "/not_found.html", map[string]interface{}{})
	require.NoError(t, err)
	return readPageHead(t, buf.String())
}

// A page drawn in a custom brand links its stylesheet after main.css, as one drawn in a built-in
// theme does, with the data-theme its appearance writes, and names its colors-only stylesheet for
// the admin console's admin pages (#815).
func TestClientPageBrand_ACustomBrandIsLinkedByItsStylesheets(t *testing.T) {
	for _, tc := range []struct {
		appearance    record.BrandAppearance
		wantDataTheme string
	}{
		{record.BrandAppearanceAuto, ""},
		{record.BrandAppearanceLight, "light"},
		{record.BrandAppearanceDark, "dark"},
	} {
		t.Run(string(tc.appearance), func(t *testing.T) {
			logs := logtest.CaptureSlog(t)
			brand := paletteBrand(tc.appearance)

			page := ClientPageBrand(context.Background(), &defaultBrandStub{brand: brand}, "")

			assert.Regexp(t, `^/brand/9/stylesheet\.css\?v=[0-9a-f]{12}$`, page.Stylesheet)
			assert.Regexp(t, `^/brand/9/colors\.css\?v=[0-9a-f]{12}$`, page.ColorsStylesheet)
			assert.Equal(t, tc.wantDataTheme, page.DataTheme)

			head := renderNotFound(t, &defaultBrandStub{brand: brand})
			require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
			assert.Equal(t, page.Stylesheet, head.stylesheets[1])
			assert.Equal(t, tc.wantDataTheme, head.dataTheme)
			assert.Empty(t, logs.Records())
		})
	}
}

// A custom brand whose stored palette cannot be drawn is drawn as a brand with an unknown theme is:
// automatic, in main.css's colors, with no brand stylesheet, and the fault is logged.
func TestRender_ACustomBrandWithAPaletteThatCannotBeDrawnIsAnUnknownTheme(t *testing.T) {
	noPalette := paletteBrand(record.BrandAppearanceDark)
	noPalette.Palette = nil
	notAColor := paletteBrand(record.BrandAppearanceDark)
	notAColor.Palette.Dark["ink"] = "red"
	missing := paletteBrand(record.BrandAppearanceLight)
	delete(missing.Palette.Light, "focus")

	for name, brand := range map[string]*record.Brand{"no palette": noPalette, "a value not a color": notAColor, "a token missing": missing} {
		t.Run(name, func(t *testing.T) {
			logs := logtest.CaptureSlog(t)

			page := ClientPageBrand(context.Background(), &defaultBrandStub{brand: brand}, "")
			assert.Equal(t, PageBrand{}, page)

			head := renderNotFound(t, &defaultBrandStub{brand: brand})
			assert.False(t, head.hasDataTheme, "got data-theme %q", head.dataTheme)
			require.Len(t, head.stylesheets, 1, "main.css alone")

			var messages []string
			for _, record := range logs.Records() {
				messages = append(messages, record.Message)
			}
			assert.Equal(t, []string{"unable to link the brand's stylesheet", "unable to link the brand's stylesheet"}, messages,
				"one for each draw")
		})
	}

	// The data layer reads a stored value that does not parse as no palette, so the case above
	// is also the one of a palette the database holds in some other shape.
	_, err := brandthemes.StylesheetPath(noPalette, brandasset.Slots{})
	assert.ErrorContains(t, err, "brand 9")
}
