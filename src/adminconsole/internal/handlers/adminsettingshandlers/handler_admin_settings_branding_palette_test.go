package adminsettingshandlers

import (
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

// A brand on a custom palette in the editor before the editor has its Colors section (#815 slice
// 4): its save sends the theme custom with the palette the admin API answered, unchanged, so a
// change to anything else keeps the palette; a built-in theme picked in its place is sent with no
// palette, which drops it.

// storedPalette is a basic palette as the admin API answers it, four colors a mode.
func storedPalette() *api.BrandPaletteResponse {
	return &api.BrandPaletteResponse{Mode: "basic",
		Light: map[string]string{"canvas": "#f4f4f4", "surface": "#ffffff", "ink": "#222222", "brand": "#777777"},
		Dark:  map[string]string{"canvas": "#0f1217", "surface": "#171b22", "ink": "#e6e8ec", "brand": "#8ab4ff"}}
}

// withCustomBrand is the auth server holding brand 8 too, on the custom theme.
func withCustomBrand() *brandingAPI {
	apiClient := newBrandingAPI()
	apiClient.brands = append(apiClient.brands, api.BrandResponse{Id: 8, Name: "Custom", Appearance: "auto",
		Theme: "custom", Palette: storedPalette()})
	return apiClient
}

func saveBrand8(t *testing.T, apiClient *brandingAPI, form url.Values) {
	t.Helper()
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)

	HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/8/edit", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "8"), handlertest.WithForm(form)))
}

func TestHandleBrandPost_ACustomBrandIsSavedWithItsPaletteUnchanged(t *testing.T) {
	apiClient := withCustomBrand()

	saveBrand8(t, apiClient, withValues(slotsForm("", "", "", "", "", ""), url.Values{
		"name": {"Renamed"}, "appearance": {"light"}, "theme": {"custom"},
		"corners": {"rounded"}, "font": {"system-ui"}, "backgroundFit": {"cover"}}))

	require.NotNil(t, apiClient.updated)
	assert.Equal(t, "custom", apiClient.updated.Theme)
	assert.Equal(t, "Renamed", apiClient.updated.Name)
	assert.Equal(t, &api.BrandPalette{Mode: "basic",
		Light: map[string]string{"canvas": "#f4f4f4", "surface": "#ffffff", "ink": "#222222", "brand": "#777777"},
		Dark:  map[string]string{"canvas": "#0f1217", "surface": "#171b22", "ink": "#e6e8ec", "brand": "#8ab4ff"}},
		apiClient.updated.Palette)
}

func TestHandleBrandPost_ABuiltInThemePickedOverACustomOneSendsNoPalette(t *testing.T) {
	apiClient := withCustomBrand()

	saveBrand8(t, apiClient, withValues(slotsForm("", "", "", "", "", ""), url.Values{
		"name": {"Custom"}, "appearance": {"auto"}, "theme": {"plum", "custom"},
		"corners": {"rounded"}, "font": {"system-ui"}, "backgroundFit": {"cover"}}))

	require.NotNil(t, apiClient.updated)
	assert.Equal(t, "plum", apiClient.updated.Theme)
	assert.Nil(t, apiClient.updated.Palette)
}

// A brand on a built-in theme is saved with no palette, as before.
func TestHandleBrandPost_ABuiltInBrandIsSavedWithNoPalette(t *testing.T) {
	apiClient := withCustomBrand()
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)

	HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/6/edit", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "6"), handlertest.WithForm(withValues(slotsForm("", "", "", "", "", ""), url.Values{
				"name": {"Spring"}, "appearance": {"light"}, "theme": {"plum"},
				"corners": {"rounded"}, "font": {"system-ui"}, "backgroundFit": {"cover"}}))))

	require.NotNil(t, apiClient.updated)
	assert.Nil(t, apiClient.updated.Palette)
}
