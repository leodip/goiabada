package render

import (
	"context"
	"maps"
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
)

// A page drawn in safe mode links its brand's safe stylesheet in place of its full one, and takes
// everything else from its brand as usual: its data-theme, its logo, its favicon and its footer
// (#816 decision 1). Safe mode comes from the operator's switch, for every page, or from a sign-in
// that asked for it, for that sign-in's pages.

// safeModeBrand is a dark brand on a custom palette with custom CSS, a logo and a footer contact:
// a brand whose full and safe stylesheets differ.
func safeModeBrand() *record.Brand {
	light := map[string]string{}
	for _, token := range []string{"canvas", "surface", "subtle", "line", "line-strong", "ink", "ink-muted",
		"brand", "brand-strong", "on-brand", "brand-soft", "danger", "danger-strong", "on-danger", "danger-soft",
		"danger-ink", "positive-soft", "positive-ink", "caution-soft", "caution-ink", "note-soft", "note-ink", "focus"} {
		light[token] = "#777777"
	}
	brand := record.NewBrand("Night", record.BrandAppearanceDark, record.BrandThemeCustom)
	brand.Id = 7
	brand.Palette = &record.BrandPalette{Mode: record.BrandPaletteModeAdvanced, Light: light, Dark: maps.Clone(light)}
	brand.CustomCSS = ".auth-card { border-width: 3px; }"
	brand.SupportEmail = "help@example.com"
	return &brand
}

// renderSafeModePage draws the not-found page in ctx, the default brand being brand and the brand of
// app-1 being client, and answers its head.
func renderSafeModePage(t *testing.T, ctx context.Context, brand, client *record.Brand) (pageHead, string) {
	t.Helper()
	ctx = reqctx.WithSettings(ctx, &record.Settings{AppName: "Test"})
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	brands := &defaultBrandStub{brand: brand, clients: map[string]*record.Brand{"app-1": client}}
	buf, err := New(web.TemplateFS(), web.StaticFS(), brands).RenderTemplateToBuffer(req,
		"/layouts/no_menu_layout.html", "/not_found.html", map[string]interface{}{})
	require.NoError(t, err)
	return readPageHead(t, buf.String()), buf.String()
}

func safeLinks(t *testing.T, brand *record.Brand) (full, safe string) {
	t.Helper()
	full, err := brandthemes.StylesheetPath(brand, brandasset.Slots{})
	require.NoError(t, err)
	safe, err = brandthemes.SafeStylesheetPath(brand, brandasset.Slots{})
	require.NoError(t, err)
	require.Regexp(t, `^/brand/7/safe-stylesheet\.css\?v=[0-9a-f]{12}$`, safe)
	require.NotEqual(t, full, safe)
	return full, safe
}

func TestRender_APageInSafeModeLinksTheSafeStylesheet(t *testing.T) {
	brand := safeModeBrand()
	full, safe := safeLinks(t, brand)

	for _, tc := range []struct {
		name     string
		ctx      func() context.Context
		wantHref string
	}{
		{
			name:     "no safe mode",
			ctx:      func() context.Context { return reqctx.WithPageClient(context.Background(), &reqctx.PageClient{}) },
			wantHref: full,
		},
		{
			name: "the operator's switch",
			ctx: func() context.Context {
				return reqctx.WithBrandSafeMode(reqctx.WithPageClient(context.Background(), &reqctx.PageClient{}))
			},
			wantHref: safe,
		},
		{
			name:     "the operator's switch on a page with no page client",
			ctx:      func() context.Context { return reqctx.WithBrandSafeMode(context.Background()) },
			wantHref: safe,
		},
		{
			name: "a sign-in that asked for it",
			ctx: func() context.Context {
				ctx := reqctx.WithPageClient(context.Background(), &reqctx.PageClient{})
				reqctx.KeepPageSafeMode(ctx)
				return ctx
			},
			wantHref: safe,
		},
		{
			name: "a sign-in that asked for it, then forgotten",
			ctx: func() context.Context {
				ctx := reqctx.WithPageClient(context.Background(), &reqctx.PageClient{})
				reqctx.KeepPageSafeMode(ctx)
				reqctx.ForgetPageClient(ctx)
				return ctx
			},
			wantHref: full,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			head, page := renderSafeModePage(t, tc.ctx(), brand, nil)

			require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
			assert.Equal(t, tc.wantHref, head.stylesheets[1])
			assert.Equal(t, "dark", head.dataTheme, "the appearance stays")
			assert.Contains(t, page, "help@example.com", "the footer stays")
		})
	}
}

// A sign-in's safe mode follows the client it is drawn for: the client's brand is linked by its safe
// stylesheet.
func TestRender_ASafeSignInIsDrawnInItsClientsSafeStylesheet(t *testing.T) {
	client := safeModeBrand()
	_, safe := safeLinks(t, client)
	defaultBrand := &record.Brand{Id: 3, Name: "Default", Appearance: record.BrandAppearanceLight, Theme: "plum"}

	ctx := reqctx.WithPageClient(context.Background(), &reqctx.PageClient{})
	reqctx.NamePageClient(ctx, "app-1")
	reqctx.KeepPageSafeMode(ctx)
	head, _ := renderSafeModePage(t, ctx, defaultBrand, client)

	require.Len(t, head.stylesheets, 2)
	assert.Equal(t, safe, head.stylesheets[1])
	assert.Equal(t, "dark", head.dataTheme)
}

// A brand names its safe stylesheets whatever the mode, which the public settings carry, and links
// them in place of its own while in safe mode.
func TestClientPageBrand_NamesTheSafeStylesheets(t *testing.T) {
	brand := safeModeBrand()
	full, safe := safeLinks(t, brand)
	colors, err := brandthemes.ColorsStylesheetPath(brand)
	require.NoError(t, err)
	safeColors, err := brandthemes.SafeColorsStylesheetPath(brand)
	require.NoError(t, err)
	require.Regexp(t, `^/brand/7/safe-colors\.css\?v=[0-9a-f]{12}$`, safeColors)

	page := ClientPageBrand(context.Background(), &defaultBrandStub{brand: brand}, "")
	assert.Equal(t, full, page.Stylesheet)
	assert.Equal(t, colors, page.ColorsStylesheet)
	assert.Equal(t, safe, page.SafeStylesheet)
	assert.Equal(t, safeColors, page.SafeColorsStylesheet)

	page = ClientPageBrand(reqctx.WithBrandSafeMode(context.Background()), &defaultBrandStub{brand: brand}, "")
	assert.Equal(t, safe, page.Stylesheet)
	assert.Equal(t, safeColors, page.ColorsStylesheet)
	assert.Equal(t, safe, page.SafeStylesheet)
	assert.Equal(t, safeColors, page.SafeColorsStylesheet)
}

// A custom brand whose palette cannot be drawn has no stylesheet of its own, and in safe mode is
// still linked by its safe one, which never reads the palette.
func TestClientPageBrand_SafeModeDrawsABrandWhosePaletteCannotBeDrawn(t *testing.T) {
	brand := safeModeBrand()
	brand.Palette = nil

	page := ClientPageBrand(context.Background(), &defaultBrandStub{brand: brand}, "")
	assert.Empty(t, page.Stylesheet, "out of safe mode it is an unknown theme")

	page = ClientPageBrand(reqctx.WithBrandSafeMode(context.Background()), &defaultBrandStub{brand: brand}, "")
	assert.Regexp(t, `^/brand/7/safe-stylesheet\.css\?v=[0-9a-f]{12}$`, page.Stylesheet)
	assert.Regexp(t, `^/brand/7/safe-colors\.css\?v=[0-9a-f]{12}$`, page.ColorsStylesheet)
}
