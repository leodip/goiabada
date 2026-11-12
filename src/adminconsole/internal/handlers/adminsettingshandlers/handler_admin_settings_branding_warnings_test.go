package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// The warnings of a saved brand (#815 decisions 5, 9 and 11): the failing pairs listed at the foot of
// the Colors section, from the brand's contrastWarnings, each with the pair's two colors, read from
// its colors; the count line above them; the saved notice's sentence; and the brand list's marker.

// failingBrand is brand 8, a basic custom palette whose colors are fullColors' "c0de" and "d0de",
// answered with two failing pairs: muted text on the soft brand background in light, and the border
// on the card in dark.
func failingBrand() api.BrandResponse {
	brand := withCustomBrands().brands[4]
	brand.ContrastWarnings = []api.BrandContrastWarning{
		{Mode: "light", Foreground: "ink-muted", Background: "brand-soft", Ratio: 3.91, Minimum: 4.5},
		{Mode: "dark", Foreground: "line", Background: "surface", Ratio: 2.1, Minimum: 3},
	}
	return brand
}

// A custom brand's editor lists its failing pairs, in the answer's order, each in decision 11's
// words with the two colors its swatch is drawn in, under a count line saying how many there are.
func TestHandleBrandGet_ACustomBrandListsItsFailingPairs(t *testing.T) {
	apiClient := withCustomBrands()
	apiClient.brands[4] = failingBrand()

	bind := getBrand(t, apiClient, "8")

	assert.Equal(t, &BrandContrastWarnings{
		CountLine: "2 pairs are below their minimum. Text and boundaries drawn in them do not meet WCAG 2.2 level AA contrast.",
		Notice:    "2 pairs of its colors are below their contrast minimum.",
		Items: []BrandContrastWarningItem{
			{Mode: "light", Foreground: "#c0de06", Background: "#c0de10",
				Text: "Light: Muted text on Soft brand background, 3.91:1. Minimum 4.5:1."},
			{Mode: "dark", Foreground: "#d0de03", Background: "#d0de01",
				Text: "Dark: Border on Card, 2.1:1. Minimum 3:1."},
		},
	}, bind["paletteWarnings"])
}

// One failing pair is counted in the singular, and a palette with none says every pair meets its
// minimum, listing nothing.
func TestNewBrandContrastWarnings_CountsOneAndNone(t *testing.T) {
	ctx := context.Background()
	one := failingBrand()
	one.ContrastWarnings = one.ContrastWarnings[:1]

	warnings := NewBrandContrastWarnings(ctx, one)
	require.NotNil(t, warnings)
	assert.Equal(t, "1 pair is below its minimum. Text and boundaries drawn in it do not meet WCAG 2.2 level AA contrast.", warnings.CountLine)
	assert.Equal(t, "1 pair of its colors is below its contrast minimum.", warnings.Notice)
	assert.Len(t, warnings.Items, 1)

	none := failingBrand()
	none.ContrastWarnings = []api.BrandContrastWarning{}
	assert.Equal(t, &BrandContrastWarnings{CountLine: "Every pair meets its minimum."}, NewBrandContrastWarnings(ctx, none))
}

// The ratio and the minimum are written as the page's language writes a number, the ratio to the two
// decimals the admin API cut it to.
func TestNewBrandContrastWarnings_WritesTheNumbersInThePagesLanguage(t *testing.T) {
	brand := failingBrand()
	brand.ContrastWarnings = append(brand.ContrastWarnings,
		api.BrandContrastWarning{Mode: "light", Foreground: "focus", Background: "canvas", Ratio: 2.99, Minimum: 3})

	warnings := NewBrandContrastWarnings(i18n.WithLocale(context.Background(), true, "pt-BR"), brand)

	require.NotNil(t, warnings)
	require.Len(t, warnings.Items, 3)
	assert.Equal(t, "Claro: Texto atenuado sobre Fundo suave da marca, 3,91:1. Mínimo 4,5:1.", warnings.Items[0].Text)
	assert.Equal(t, "Escuro: Borda sobre Cartão, 2,1:1. Mínimo 3:1.", warnings.Items[1].Text)
	assert.Equal(t, "Claro: Anel de foco sobre Fundo, 2,99:1. Mínimo 3:1.", warnings.Items[2].Text)
	assert.Equal(t, "3 pares estão abaixo do seu mínimo. Textos e contornos desenhados nessas cores não atendem ao contraste do nível AA da WCAG 2.2.", warnings.CountLine)
}

// A pair naming a color the console has no label for, as a newer auth server's could, is named by
// its token, and a color the brand's colors do not hold draws no fill rather than a value that is not
// a color.
func TestNewBrandContrastWarnings_AnUnknownColorIsNamedByItsToken(t *testing.T) {
	brand := failingBrand()
	brand.Colors.Light["glow"] = "url(#x)"
	brand.ContrastWarnings = []api.BrandContrastWarning{{Mode: "light", Foreground: "glow", Background: "halo", Ratio: 1.5, Minimum: 3}}

	warnings := NewBrandContrastWarnings(context.Background(), brand)

	require.NotNil(t, warnings)
	assert.Equal(t, []BrandContrastWarningItem{{Mode: "light", Text: "Light: glow on halo, 1.5:1. Minimum 3:1."}}, warnings.Items)
}

// A brand on a built-in theme, and a custom brand whose stored palette cannot be read, have no list:
// there is no palette of theirs to list pairs of.
func TestNewBrandContrastWarnings_NoneWithoutAStoredPalette(t *testing.T) {
	ctx := context.Background()
	builtIn := withCustomBrands().brands[0]
	builtIn.Colors = &api.BrandColors{Light: fullColors("c0de"), Dark: fullColors("d0de")}
	builtIn.ContrastWarnings = []api.BrandContrastWarning{}
	assert.Nil(t, NewBrandContrastWarnings(ctx, builtIn))

	unreadable := api.BrandResponse{Id: 8, Theme: "custom", ContrastWarnings: []api.BrandContrastWarning{}}
	assert.Nil(t, NewBrandContrastWarnings(ctx, unreadable))

	assert.Nil(t, getBrand(t, newBrandingAPI(), "4")["paletteWarnings"])
}

// A refused form holds the colors as typed, which the stored brand's warnings do not describe, so it
// lists none.
func TestHandleBrandPost_ARefusedFormListsNoStoredWarnings(t *testing.T) {
	apiClient := withCustomBrands()
	apiClient.brands[4] = failingBrand()

	bind := postBrand(t, apiClient, "8",
		withValues(brandFields("custom", "auto"), paletteFields("basic", fullColors("c0de"), fullColors("d0de"))),
		refusal("BRAND_NAME_IN_USE", "In use."))

	assert.Nil(t, bind["paletteWarnings"])
}

// After saving an existing brand, its page says it was saved and lists the brand's failing pairs, as
// the admin API answers them on the read that draws the page.
func TestHandleBrandPost_TheSavedPageListsTheBrandsFailingPairs(t *testing.T) {
	store := newSettingsTestStore()
	apiClient := newBrandingAPI()
	failing := failingBrand()
	failing.Id = 4
	apiClient.brands[0] = failing
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	w := httptest.NewRecorder()

	HandleBrandPost(httpHelper, store, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(w,
		handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "4"),
			handlertest.WithForm(withValues(brandFields("custom", "auto"), paletteFields("basic", fullColors("c0de"), fullColors("d0de"))))))
	require.Equal(t, "https://console.example.test/admin/settings/branding/4/edit", w.Header().Get("Location"))

	bind := editPageAfter(t, store, apiClient, w)
	assert.Equal(t, true, bind["savedSuccessfully"])
	warnings, ok := bind["paletteWarnings"].(*BrandContrastWarnings)
	require.True(t, ok)
	require.NotNil(t, warnings)
	assert.Equal(t, "2 pairs of its colors are below their contrast minimum.", warnings.Notice)
	assert.Len(t, warnings.Items, 2)
}

// A brand created with a failing palette goes back to the brand list, as any creation does, with no
// notice: the list marks it there.
func TestHandleBrandNewPost_AFailingPaletteGoesBackToTheList(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := newBrandingAPI()
	w := httptest.NewRecorder()

	HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(w,
		handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
			handlertest.WithForm(withValues(brandFields("custom", "auto"),
				paletteFields("basic", map[string]string{"canvas": "#767676", "surface": "#767676", "ink": "#ffffff", "brand": "#ffffff"},
					map[string]string{"canvas": "#000000", "surface": "#000000", "ink": "#000000", "brand": "#000000"})))))

	require.NotNil(t, apiClient.created)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://console.example.test/admin/settings/branding", w.Header().Get("Location"))
	assert.Empty(t, w.Result().Cookies(), "no notice is set")
}

// The brand list marks each brand with failing pairs, saying how many, and leaves a brand with none,
// or with no colors to check, unmarked.
func TestHandleBrandingGet_MarksABrandWithFailingPairs(t *testing.T) {
	apiClient := withCustomBrands()
	apiClient.brands[4] = failingBrand()
	one := failingBrand()
	one.ContrastWarnings = one.ContrastWarnings[1:]
	apiClient.brands[5].ContrastWarnings = one.ContrastWarnings
	apiClient.brands[0].ContrastWarnings = []api.BrandContrastWarning{}

	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding.html").Once()
	HandleBrandingGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding", handlertest.WithAccessToken()))

	rows := handlertest.Bind(t, httpHelper)["brands"].([]BrandRow)
	require.Len(t, rows, 6)
	assert.Empty(t, rows[0].WarningsMarker, "no failing pair")
	assert.Empty(t, rows[1].WarningsMarker, "no answer of warnings")
	assert.Equal(t, "2 pairs below contrast minimum", rows[4].WarningsMarker)
	assert.Equal(t, "1 pair below contrast minimum", rows[5].WarningsMarker)
}

// A saved custom brand's Custom card is drawn in the colors the brand is drawn in, a basic palette's
// worked-out ones included, which its swatch shows: the border and the muted text.
func TestHandleBrandGet_TheCustomCardIsDrawnInTheBrandsColors(t *testing.T) {
	swatch := paletteOf(t, getBrand(t, withCustomBrands(), "8")).Swatch

	assert.Equal(t, BrandPaletteSwatch{Light: fullColors("c0de"), Dark: fullColors("d0de")}, swatch)
	assert.Equal(t, "#c0de03", swatch.Light["line"])
	assert.Equal(t, "#d0de06", swatch.Dark["ink-muted"])
}
