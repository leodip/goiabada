package adminsettingshandlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// The brand editor's Colors section (#815 decision 7): the fields a custom palette is typed in, what
// they start with, what a save sends, and each refusal at its field. The columns follow the
// appearance, and a column the appearance hides comes back while it holds a value that is not a
// color (decision 8).

// paletteTokens are the 23 color tokens, as ui.css declares them.
var paletteTokens = []string{
	"canvas", "surface", "subtle", "line", "line-strong", "ink", "ink-muted",
	"brand", "brand-strong", "on-brand", "brand-soft",
	"danger", "danger-strong", "on-danger", "danger-soft", "danger-ink",
	"positive-soft", "positive-ink", "caution-soft", "caution-ink", "note-soft", "note-ink",
	"focus",
}

// fullColors is a value for each of the 23 tokens that no theme has: the prefix and the token's place,
// so "c0de" gives canvas #c0de00 and focus #c0de22.
func fullColors(prefix string) map[string]string {
	colors := make(map[string]string, len(paletteTokens))
	for i, token := range paletteTokens {
		colors[token] = fmt.Sprintf("#%s%02d", prefix, i)
	}
	return colors
}

// basicOf is the four colors a basic palette is entered with, taken from colors.
func basicOf(colors map[string]string) map[string]string {
	return map[string]string{"canvas": colors["canvas"], "surface": colors["surface"], "ink": colors["ink"], "brand": colors["brand"]}
}

// withCustomBrands is the auth server holding brand 8 too, on a basic custom palette, and brand 9 on
// an advanced one, as the admin API answers them: the palette as written, and the 23 colors each mode
// is drawn in.
func withCustomBrands() *brandingAPI {
	apiClient := newBrandingAPI()
	apiClient.brands = append(apiClient.brands,
		api.BrandResponse{Id: 8, Name: "Custom", Appearance: "auto", Theme: "custom",
			Palette: &api.BrandPaletteResponse{Mode: "basic", Light: basicOf(fullColors("c0de")), Dark: basicOf(fullColors("d0de"))},
			Colors:  &api.BrandColors{Light: fullColors("c0de"), Dark: fullColors("d0de")}},
		api.BrandResponse{Id: 9, Name: "Advanced", Appearance: "light", Theme: "custom",
			Palette: &api.BrandPaletteResponse{Mode: "advanced", Light: fullColors("a0de"), Dark: fullColors("b0de")},
			Colors:  &api.BrandColors{Light: fullColors("a0de"), Dark: fullColors("b0de")}})
	return apiClient
}

// paletteFields is the Colors section's fields as the editor posts them: the mode, and a value for
// each token of each mode, from light and dark.
func paletteFields(mode string, light, dark map[string]string) url.Values {
	form := url.Values{"paletteMode": {mode}}
	for _, token := range paletteTokens {
		form.Set("palette-light-"+token, light[token])
		form.Set("palette-dark-"+token, dark[token])
	}
	return form
}

// brandFields is the rest of a brand's form, for the theme and appearance named.
func brandFields(theme, appearance string) url.Values {
	return withValues(slotsForm("", "", "", "", "", ""), url.Values{
		"name": {"Custom"}, "appearance": {appearance}, "theme": {theme},
		"corners": {"rounded"}, "font": {"system-ui"}, "backgroundFit": {"cover"}})
}

func paletteOf(t *testing.T, bind map[string]interface{}) BrandPaletteView {
	t.Helper()
	view, ok := bind["palette"].(BrandPaletteView)
	require.True(t, ok, "the page is bound the Colors section")
	return view
}

func getBrand(t *testing.T, apiClient *brandingAPI, id string) map[string]interface{} {
	t.Helper()
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()

	HandleBrandGet(httpHelper, newSettingsTestStore(), apiClient).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding/"+id+"/edit", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", id)))
	return handlertest.Bind(t, httpHelper)
}

// postBrand saves brand id with form, refused with refusal when it is not nil, and answers the page
// drawn again, or nil when the save went through.
func postBrand(t *testing.T, apiClient *brandingAPI, id string, form url.Values, refusal error) map[string]interface{} {
	t.Helper()
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient.writeErr = refusal
	if refusal != nil {
		handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()
	}

	HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/"+id+"/edit", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", id), handlertest.WithForm(form)))
	if refusal == nil {
		return nil
	}
	return handlertest.Bind(t, httpHelper)
}

// A new brand's fields hold the first theme's colors, which the form starts on, in basic mode; the
// brand has no palette, so the first pick of Custom may replace them (decision 7).
func TestHandleBrandNewGet_TheColorsStartAsTheFirstThemesInBasicMode(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()

	HandleBrandNewGet(httpHelper, newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding/new", handlertest.WithAccessToken()))

	assert.Equal(t, BrandPaletteForm{Mode: "basic", Fresh: true,
		Light: map[string]string{"canvas": "#000001", "surface": "#000002"},
		Dark:  map[string]string{"canvas": "#000003", "surface": "#000004"}},
		paletteOf(t, handlertest.Bind(t, httpHelper)).BrandPaletteForm)
}

// A brand on a built-in theme has no palette: its fields hold its own theme's colors.
func TestHandleBrandGet_ABuiltInBrandsColorsAreItsThemes(t *testing.T) {
	bind := getBrand(t, newBrandingAPI(), "6")

	assert.Equal(t, BrandPaletteForm{Mode: "basic", Fresh: true,
		Light: map[string]string{"canvas": "#000011", "surface": "#000012"},
		Dark:  map[string]string{"canvas": "#000013", "surface": "#000014"}},
		paletteOf(t, bind).BrandPaletteForm)
}

// A basic palette's fields hold the 23 colors the brand is drawn in, so Advanced shows the worked-out
// ones; an advanced palette's hold the 23 as written.
func TestHandleBrandGet_ACustomBrandsColorsAreItsStoredOnes(t *testing.T) {
	assert.Equal(t, BrandPaletteForm{Mode: "basic", StoredMode: "basic", Light: fullColors("c0de"), Dark: fullColors("d0de")},
		paletteOf(t, getBrand(t, withCustomBrands(), "8")).BrandPaletteForm)
	assert.Equal(t, BrandPaletteForm{Mode: "advanced", StoredMode: "advanced", Light: fullColors("a0de"), Dark: fullColors("b0de")},
		paletteOf(t, getBrand(t, withCustomBrands(), "9")).BrandPaletteForm)
}

// A basic palette is sent with its four colors a mode, trimmed, whatever the other 19 fields hold;
// both modes are sent whatever the appearance (decision 2).
func TestHandleBrandPost_ABasicPaletteSendsItsFourColorsAMode(t *testing.T) {
	apiClient := withCustomBrands()
	light, dark := fullColors("e0de"), fullColors("f0de")
	light["brand"] = "  #AbCdEf "

	postBrand(t, apiClient, "8", withValues(brandFields("custom", "light"), paletteFields("basic", light, dark)), nil)

	require.NotNil(t, apiClient.updated)
	assert.Equal(t, "custom", apiClient.updated.Theme)
	assert.Equal(t, &api.BrandPalette{Mode: "basic",
		Light: map[string]string{"canvas": "#e0de00", "surface": "#e0de01", "ink": "#e0de05", "brand": "#AbCdEf"},
		Dark:  map[string]string{"canvas": "#f0de00", "surface": "#f0de01", "ink": "#f0de05", "brand": "#f0de07"}},
		apiClient.updated.Palette)
}

// An advanced palette is sent with all 23 colors of each mode.
func TestHandleBrandPost_AnAdvancedPaletteSendsAll23ColorsAMode(t *testing.T) {
	apiClient := withCustomBrands()

	postBrand(t, apiClient, "8", withValues(brandFields("custom", "auto"), paletteFields("advanced", fullColors("e0de"), fullColors("f0de"))), nil)

	require.NotNil(t, apiClient.updated)
	assert.Equal(t, &api.BrandPalette{Mode: "advanced", Light: fullColors("e0de"), Dark: fullColors("f0de")}, apiClient.updated.Palette)
}

// A built-in theme is sent with no palette, which drops a stored one, whatever the Colors section
// holds (decision 2).
func TestHandleBrandPost_ABuiltInThemeSendsNoPalette(t *testing.T) {
	apiClient := withCustomBrands()

	postBrand(t, apiClient, "8", withValues(brandFields("plum", "auto"), paletteFields("basic", fullColors("e0de"), fullColors("f0de"))), nil)

	require.NotNil(t, apiClient.updated)
	assert.Equal(t, "plum", apiClient.updated.Theme)
	assert.Nil(t, apiClient.updated.Palette)
}

// A new brand is created with the palette the form holds.
func TestHandleBrandNewPost_ACustomBrandIsCreatedWithItsPalette(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := newBrandingAPI()

	HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
			handlertest.WithForm(withValues(brandFields("custom", "dark"), paletteFields("basic", fullColors("e0de"), fullColors("f0de"))))))

	require.NotNil(t, apiClient.created)
	assert.Equal(t, "custom", apiClient.created.Theme)
	assert.Equal(t, &api.BrandPalette{Mode: "basic", Light: basicOf(fullColors("e0de")), Dark: basicOf(fullColors("f0de"))},
		apiClient.created.Palette)
}

// Each refusal of a palette is shown at the field its error_field points at, and the form is drawn
// again with what was typed (decision 7). The mode's refusal is at the Basic and Advanced choice.
func TestHandleBrandPost_EachPaletteRefusalIsShownAtItsField(t *testing.T) {
	for _, tc := range []struct {
		code, pointer, field string
	}{
		{"handler.brand.palette_color_invalid", "/palette/light/canvas", "palette-light-canvas"},
		{"handler.brand.palette_color_invalid", "/palette/dark/brand", "palette-dark-brand"},
		{"handler.brand.palette_color_required", "/palette/dark/ink-muted", "palette-dark-ink-muted"},
		{"handler.brand.palette_mode_invalid", "/palette/mode", "paletteMode"},
		// A member the form has no field for names none, so the focus stays on the name.
		{"handler.brand.palette_color_unknown", "/palette/dark/glow", ""},
		{"handler.brand.palette_color_invalid", "/palette/sepia/brand", ""},
		{"handler.brand.palette_color_invalid", "/palette/dark/brand/0", ""},
		{"handler.brand.palette_colors_required", "/palette/dark", ""},
	} {
		t.Run(tc.pointer, func(t *testing.T) {
			light, dark := fullColors("e0de"), fullColors("f0de")
			dark["brand"] = "#12345"

			bind := postBrand(t, withCustomBrands(), "8",
				withValues(brandFields("custom", "auto"), paletteFields("advanced", light, dark)),
				refusalAt(tc.code, "Not that.", tc.pointer))

			assert.Equal(t, tc.field, bind["errorField"])
			want := fullColors("f0de")
			want["brand"] = "#12345"
			assert.Equal(t, BrandPaletteForm{Mode: "advanced", StoredMode: "basic", Light: fullColors("e0de"), Dark: want},
				paletteOf(t, bind).BrandPaletteForm, "with what was typed")
		})
	}
}

// A form drawn again keeps saying whether the fields still hold the theme colors nothing changed.
func TestHandleBrandPost_ARefusedFormKeepsWhetherItsColorsAreUntouched(t *testing.T) {
	for _, fresh := range []bool{true, false} {
		form := withValues(brandFields("plum", "auto"), paletteFields("basic", fullColors("e0de"), fullColors("f0de")))
		if fresh {
			form.Set("paletteFresh", "true")
		}

		bind := postBrand(t, newBrandingAPI(), "6", form, refusal("handler.brand.name_in_use", "Taken."))

		assert.Equal(t, fresh, paletteOf(t, bind).Fresh)
		assert.Empty(t, paletteOf(t, bind).StoredMode, "brand 6 has no palette")
	}
}

// The columns follow the appearance: Automatic draws both, Light and Dark their one (decision 8). An
// appearance the console does not know is drawn as Automatic, as the preview draws it.
func TestNewBrandPaletteView_TheColumnsFollowTheAppearance(t *testing.T) {
	form := BrandPaletteForm{Mode: "basic", Light: fullColors("e0de"), Dark: fullColors("f0de")}
	for _, tc := range []struct {
		appearance  string
		light, dark bool
	}{
		{"auto", true, true},
		{"light", true, false},
		{"dark", false, true},
		{"sepia", true, true},
	} {
		view := NewBrandPaletteView(form, tc.appearance, "")
		assert.Equal(t, []BrandPaletteColumn{{Mode: "light", Drawn: tc.light, Shown: tc.light}, {Mode: "dark", Drawn: tc.dark, Shown: tc.dark}},
			view.Columns, tc.appearance)
		for _, group := range view.Groups {
			for _, row := range group.Rows {
				assert.Equal(t, tc.light, row.Fields[0].Shown, "%s: %s light", tc.appearance, row.Token)
				assert.Equal(t, tc.dark, row.Fields[1].Shown, "%s: %s dark", tc.appearance, row.Token)
			}
		}
	}
}

// A column the appearance hides is shown while a field of a row the mode shows holds a value that is
// not a color, or is the refused one (decision 8's exception). A value in a row Basic hides does not
// bring it back, since that row is not on screen and is not sent.
func TestNewBrandPaletteView_AHiddenColumnHoldingAValueThatIsNoColorIsShown(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     string
		token    string
		value    string
		refused  string
		wantDark bool
	}{
		{"three digits", "basic", "brand", "#abc", "", true},
		{"a name", "basic", "canvas", "navy", "", true},
		{"empty", "basic", "ink", "", "", true},
		{"no #", "advanced", "focus", "123456", "", true},
		{"a row basic hides", "basic", "focus", "123456", "", false},
		{"refused", "basic", "brand", "#0f0f0f", "palette-dark-brand", true},
		{"a color", "basic", "brand", "#0F0F0F", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dark := fullColors("f0de")
			dark[tc.token] = tc.value

			view := NewBrandPaletteView(BrandPaletteForm{Mode: tc.mode, Light: fullColors("e0de"), Dark: dark}, "light", tc.refused)

			assert.Equal(t, []BrandPaletteColumn{{Mode: "light", Drawn: true, Shown: true}, {Mode: "dark", Drawn: false, Shown: tc.wantDark}},
				view.Columns)
			field := fieldOf(t, view, "dark", tc.token)
			assert.Equal(t, tc.wantDark, field.Shown)
			assert.Equal(t, tc.refused != "", field.Refused)
		})
	}
}

func fieldOf(t *testing.T, view BrandPaletteView, mode, token string) BrandPaletteField {
	t.Helper()
	for _, group := range view.Groups {
		for _, row := range group.Rows {
			for _, field := range row.Fields {
				if row.Token == token && field.Mode == mode {
					return field
				}
			}
		}
	}
	t.Fatalf("no %s %s field", mode, token)
	return BrandPaletteField{}
}

// Each field: its id, which is its name, its value as typed, and the color well beside it, which holds
// the value in lower case while it is a color and black while it is not; a value that is not a color
// is marked.
func TestNewBrandPaletteView_EachFieldHoldsItsValueAndItsWell(t *testing.T) {
	light := fullColors("e0de")
	light["brand"] = "#ABCDEF"
	light["ink"] = "#abcd"

	view := NewBrandPaletteView(BrandPaletteForm{Mode: "basic", Light: light, Dark: fullColors("f0de")}, "auto", "")

	assert.Equal(t, BrandPaletteField{Id: "palette-light-brand", Mode: "light", Value: "#ABCDEF", Well: "#abcdef", Shown: true},
		fieldOf(t, view, "light", "brand"))
	assert.Equal(t, BrandPaletteField{Id: "palette-light-ink", Mode: "light", Value: "#abcd", Well: "#000000", Shown: true, Invalid: true},
		fieldOf(t, view, "light", "ink"))
	assert.Equal(t, BrandPaletteField{Id: "palette-dark-line-strong", Mode: "dark", Value: "#f0de04", Well: "#f0de04", Shown: true},
		fieldOf(t, view, "dark", "line-strong"))
}

// Advanced shows the 23 colors in four groups, page, text, brand and status, each a row with its
// label; Basic shows the four rows of background, card, text and brand color (decision 7).
func TestNewBrandPaletteView_GroupsTheColorsAndMarksTheBasicFour(t *testing.T) {
	view := NewBrandPaletteView(BrandPaletteForm{Mode: "advanced", Light: fullColors("e0de"), Dark: fullColors("f0de")}, "auto", "")

	type row struct {
		Token, Label string
		Basic        bool
	}
	want := map[string][]row{
		"page": {{"canvas", "canvas", true}, {"surface", "surface", true}, {"subtle", "subtle", false},
			{"line", "line", false}, {"line-strong", "line_strong", false}},
		"text":  {{"ink", "ink", true}, {"ink-muted", "ink_muted", false}},
		"brand": {{"brand", "brand", true}, {"brand-strong", "brand_strong", false}, {"on-brand", "on_brand", false}, {"brand-soft", "brand_soft", false}, {"focus", "focus", false}},
		"status": {{"danger", "danger", false}, {"danger-strong", "danger_strong", false}, {"on-danger", "on_danger", false},
			{"danger-soft", "danger_soft", false}, {"danger-ink", "danger_ink", false}, {"positive-soft", "positive_soft", false},
			{"positive-ink", "positive_ink", false}, {"caution-soft", "caution_soft", false}, {"caution-ink", "caution_ink", false},
			{"note-soft", "note_soft", false}, {"note-ink", "note_ink", false}},
	}
	var keys []string
	for _, group := range view.Groups {
		keys = append(keys, group.Key)
		assert.Equal(t, "adminconsole.admin_branding.palette.group."+group.Key, group.NameID)
		var got []row
		for _, r := range group.Rows {
			got = append(got, row{r.Token, r.LabelID, r.Basic})
			require.Len(t, r.Fields, 2)
			assert.Equal(t, "light", r.Fields[0].Mode)
			assert.Equal(t, "dark", r.Fields[1].Mode)
		}
		for i := range want[group.Key] {
			want[group.Key][i].Label = "adminconsole.admin_branding.palette.color." + want[group.Key][i].Label
		}
		assert.Equal(t, want[group.Key], got, group.Key)
	}
	assert.Equal(t, []string{"page", "text", "brand", "status"}, keys)
	assert.False(t, view.Basic)
	assert.True(t, NewBrandPaletteView(BrandPaletteForm{Mode: "basic"}, "auto", "").Basic)
}

// Going back to Basic says the other colors are worked out again at the save: shown while Basic holds
// a palette stored in Advanced (decision 7).
func TestNewBrandPaletteView_SaysBasicWorksTheOthersOutAgainOverAnAdvancedPalette(t *testing.T) {
	for _, tc := range []struct {
		mode, stored string
		note         bool
	}{
		{"basic", "advanced", true},
		{"basic", "basic", false},
		{"basic", "", false},
		{"advanced", "advanced", false},
		{"advanced", "basic", false},
	} {
		view := NewBrandPaletteView(BrandPaletteForm{Mode: tc.mode, StoredMode: tc.stored}, "auto", "")
		assert.Equal(t, tc.note, view.BasicNote, "%s over %q", tc.mode, tc.stored)
	}
}

// The Custom card's swatch shows the palette being edited: each value that is a color, in lower case,
// and nothing for one that is not.
func TestNewBrandPaletteView_TheSwatchShowsThePaletteEdited(t *testing.T) {
	light := map[string]string{"canvas": "#FFFFFF", "surface": "#f0f0f0", "ink": "url(#x)", "brand": ""}
	dark := map[string]string{"canvas": "#000000", "brand": "#123456"}

	view := NewBrandPaletteView(BrandPaletteForm{Mode: "basic", Light: light, Dark: dark}, "auto", "")

	assert.Equal(t, BrandPaletteSwatch{
		Light: map[string]string{"canvas": "#ffffff", "surface": "#f0f0f0"},
		Dark:  map[string]string{"canvas": "#000000", "brand": "#123456"},
	}, view.Swatch)
}

// The brand list and the delete page name the custom theme in words.
func TestHandleBrandingGet_NamesTheCustomTheme(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding.html").Once()

	HandleBrandingGet(httpHelper, withCustomBrands()).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding", handlertest.WithAccessToken()))

	rows := handlertest.Bind(t, httpHelper)["brands"].([]BrandRow)
	assert.Equal(t, "Custom", rows[len(rows)-1].ThemeName)
}
