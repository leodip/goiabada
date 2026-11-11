package adminsettingshandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/sessionstore"
)

// The Branding pages (#810): the brands listed with the default marked, a brand created, edited,
// made the default and deleted, each refusal on the field it is about, and the theme cards' swatches
// drawn from the auth server's own palettes.

// brandingAPI is the auth server as the Branding pages see it: the brands it holds, the themes it
// lists, and every write recorded. A write answers writeErr when it is set.
type brandingAPI struct {
	brands   []api.BrandResponse
	themes   []api.BrandThemeResponse
	assets   []api.BrandAssetResponse
	assetErr error
	writeErr error

	created     *api.CreateBrandRequest
	updatedId   int64
	updated     *api.UpdateBrandRequest
	deletedId   int64
	madeDefault int64
}

func (a *brandingAPI) GetAllBrands(context.Context, string) ([]api.BrandResponse, error) {
	return a.brands, nil
}

func (a *brandingAPI) GetBrandById(_ context.Context, _ string, brandId int64) (*api.BrandResponse, error) {
	for _, brand := range a.brands {
		if brand.Id == brandId {
			return &brand, nil
		}
	}
	return nil, &apiclient.APIError{Code: "NOT_FOUND", Message: "Brand not found", StatusCode: http.StatusNotFound}
}

func (a *brandingAPI) GetBrandAssetById(_ context.Context, _ string, assetId int64) (*api.BrandAssetResponse, error) {
	if a.assetErr != nil {
		return nil, a.assetErr
	}
	for _, asset := range a.assets {
		if asset.Id == assetId {
			return &asset, nil
		}
	}
	return nil, &apiclient.APIError{Code: "NOT_FOUND", Message: "Brand asset not found", StatusCode: http.StatusNotFound}
}

func (a *brandingAPI) GetBrandThemes(context.Context, string) ([]api.BrandThemeResponse, error) {
	return a.themes, nil
}

func (a *brandingAPI) CreateBrand(_ context.Context, _ string, request *api.CreateBrandRequest) (*api.BrandResponse, error) {
	a.created = request
	if a.writeErr != nil {
		return nil, a.writeErr
	}
	return &api.BrandResponse{Id: 9, Name: request.Name}, nil
}

func (a *brandingAPI) UpdateBrand(_ context.Context, _ string, brandId int64, request *api.UpdateBrandRequest) (*api.BrandResponse, error) {
	a.updatedId, a.updated = brandId, request
	if a.writeErr != nil {
		return nil, a.writeErr
	}
	return &api.BrandResponse{Id: brandId, Name: request.Name}, nil
}

func (a *brandingAPI) DeleteBrand(_ context.Context, _ string, brandId int64) error {
	a.deletedId = brandId
	return a.writeErr
}

func (a *brandingAPI) MakeBrandDefault(_ context.Context, _ string, brandId int64) (*api.BrandResponse, error) {
	a.madeDefault = brandId
	if a.writeErr != nil {
		return nil, a.writeErr
	}
	return &api.BrandResponse{Id: brandId, IsDefault: true}, nil
}

// Two of the auth server's themes, with values that are no theme's real ones, so a swatch drawn
// from anything but the answer cannot pass.
var (
	testBlueberry = api.BrandThemeResponse{Key: "blueberry",
		Light: map[string]string{"canvas": "#000001", "surface": "#000002"},
		Dark:  map[string]string{"canvas": "#000003", "surface": "#000004"}}
	testPlum = api.BrandThemeResponse{Key: "plum",
		Light: map[string]string{"canvas": "#000011", "surface": "#000012"},
		Dark:  map[string]string{"canvas": "#000013", "surface": "#000014"}}
)

func newBrandingAPI() *brandingAPI {
	return &brandingAPI{
		brands: []api.BrandResponse{
			{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum", ClientCount: 2,
				Corners: "pill", Font: "serif", BackgroundFit: "tile", HideAppName: true,
				Logo:        &api.BrandAssetResponse{Id: 11, Kind: "logo", Url: "https://auth.example.test/brand-assets/11?v=a", ContentType: "image/png", Width: 200, Height: 60},
				Favicon:     &api.BrandAssetResponse{Id: 13, Kind: "favicon", Url: "https://auth.example.test/brand-assets/13?v=c", ContentType: "image/png", Width: 64, Height: 64},
				RegularFont: &api.BrandAssetResponse{Id: 15, Kind: "font", Url: "https://auth.example.test/brand-assets/15?v=e", ContentType: "font/woff2"}},
			{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true, ClientCount: 3},
			{Id: 6, Name: "Spring", Appearance: "light", Theme: "plum", ClientCount: 1},
			{Id: 7, Name: "Unused", Appearance: "auto", Theme: "plum"},
		},
		themes: []api.BrandThemeResponse{testBlueberry, testPlum},
		assets: []api.BrandAssetResponse{uploadedLogo, uploadedDarkLogo, uploadedFavicon, uploadedBackground, uploadedRegularFont, uploadedBoldFont},
	}
}

// Assets uploaded in the editor and not yet saved, as the admin API answers each read by its id.
var (
	uploadedLogo        = api.BrandAssetResponse{Id: 21, Kind: "logo", Url: "https://auth.example.test/brand-assets/21?v=l", ContentType: "image/png", Width: 240, Height: 80}
	uploadedDarkLogo    = api.BrandAssetResponse{Id: 22, Kind: "logo", Url: "https://auth.example.test/brand-assets/22?v=d", ContentType: "image/webp", Width: 240, Height: 80}
	uploadedFavicon     = api.BrandAssetResponse{Id: 23, Kind: "favicon", Url: "https://auth.example.test/brand-assets/23?v=f", ContentType: "image/png", Width: 64, Height: 64}
	uploadedBackground  = api.BrandAssetResponse{Id: 24, Kind: "background", Url: "https://auth.example.test/brand-assets/24?v=b", ContentType: "image/jpeg", Width: 1920, Height: 1080}
	uploadedRegularFont = api.BrandAssetResponse{Id: 25, Kind: "font", Url: "https://auth.example.test/brand-assets/25?v=r", ContentType: "font/woff2"}
	uploadedBoldFont    = api.BrandAssetResponse{Id: 26, Kind: "font", Url: "https://auth.example.test/brand-assets/26?v=o", ContentType: "font/woff2"}
)

// slotsForm is the six slots' fields as the editor posts them: each slot's asset id, or empty.
func slotsForm(logo, darkLogo, favicon, background, regularFont, boldFont string) url.Values {
	return url.Values{"logo": {logo}, "darkLogo": {darkLogo}, "favicon": {favicon}, "background": {background},
		"regularFont": {regularFont}, "boldFont": {boldFont}}
}

// withValues is form with values added.
func withValues(form url.Values, values url.Values) url.Values {
	merged := url.Values{}
	for key, value := range form {
		merged[key] = value
	}
	for key, value := range values {
		merged[key] = value
	}
	return merged
}

func refusal(code, message string) error {
	return &apiclient.APIError{Code: code, Message: message, StatusCode: http.StatusBadRequest}
}

// Each row carries how many clients the brand draws, for the list's Clients column (#812 decision 3).
func TestHandleBrandingGet_ListsTheBrandsInTheServersOrderWithTheirLookInWords(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding.html").Once()

	HandleBrandingGet(httpHelper, newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding", handlertest.WithAccessToken()))

	assert.Equal(t, []BrandRow{
		{BrandResponse: newBrandingAPI().brands[0], AppearanceName: "Dark", ThemeName: "Plum"},
		{BrandResponse: api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true, ClientCount: 3},
			AppearanceName: "Automatic", ThemeName: "Blueberry"},
		{BrandResponse: api.BrandResponse{Id: 6, Name: "Spring", Appearance: "light", Theme: "plum", ClientCount: 1},
			AppearanceName: "Light", ThemeName: "Plum"},
		{BrandResponse: api.BrandResponse{Id: 7, Name: "Unused", Appearance: "auto", Theme: "plum"},
			AppearanceName: "Automatic", ThemeName: "Plum"},
	}, handlertest.Bind(t, httpHelper)["brands"])
}

// A theme the console has no name for, as a newer auth server's could be, is named by its key
// rather than by a catalog key leaking onto the page.
func TestHandleBrandingGet_ATheConsoleDoesNotKnowIsNamedByItsKey(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding.html").Once()
	apiClient := newBrandingAPI()
	apiClient.brands = []api.BrandResponse{{Id: 6, Name: "Lab", Appearance: "light", Theme: "dragonfruit"}}

	HandleBrandingGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding", handlertest.WithAccessToken()))

	rows := handlertest.Bind(t, httpHelper)["brands"].([]BrandRow)
	require.Len(t, rows, 1)
	assert.Equal(t, "dragonfruit", rows[0].ThemeName)
	assert.Equal(t, "Light", rows[0].AppearanceName)
}

// The themes as the form draws them: in the auth server's order, each named, with the palettes it
// answered, which the swatches are drawn from.
var wantThemeOptions = []BrandThemeOption{
	{Key: "blueberry", Name: "Blueberry", Light: testBlueberry.Light, Dark: testBlueberry.Dark},
	{Key: "plum", Name: "Plum", Light: testPlum.Light, Dark: testPlum.Dark},
}

func TestHandleBrandNewGet_StartsAutomaticOnTheFirstTheme(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()

	HandleBrandNewGet(httpHelper, newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding/new", handlertest.WithAccessToken()))

	// A new brand starts as a brand nobody has changed is drawn: rounded, System UI, cover, the name
	// shown (#813 decision 2).
	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, true, bind["isNew"])
	assert.Equal(t, BrandForm{Appearance: "auto", Theme: "blueberry", Corners: "rounded", Font: "system-ui",
		BackgroundFit: "cover", HideAppName: false}, bind["brand"])
	assert.Equal(t, wantThemeOptions, bind["brandThemes"])
	assert.Equal(t, wantThemeOptions[0], bind["appearanceTheme"], "the appearance cards show the chosen theme")
}

func TestHandleBrandNewPost_CreatesTheBrandAndGoesBackToTheList(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := newBrandingAPI()
	cache := &invalidationRecorder{}
	w := httptest.NewRecorder()

	HandleBrandNewPost(httpHelper, apiClient, cache, consoleBaseURL).ServeHTTP(w,
		handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
			handlertest.WithForm(url.Values{"name": {"  Spring  "}, "appearance": {"dark"}, "theme": {"plum"},
				"corners": {"pill"}, "font": {"neo-grotesque"}, "backgroundFit": {"contain"}, "hideAppName": {"on"}})))

	// The kit's four choices are sent as the form holds them (#813 decision 10), the switch on.
	assert.Equal(t, &api.CreateBrandRequest{Name: "Spring", Appearance: "dark", Theme: "plum",
		Corners: "pill", Font: "neo-grotesque", BackgroundFit: "contain", HideAppName: true}, apiClient.created)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://console.example.test/admin/settings/branding", w.Header().Get("Location"))
	assert.Equal(t, 1, cache.invalidations)
}

// The hide-app-name switch is a checkbox, which a browser leaves out of the form when it is off, so
// a form without it sends the switch off; the choices are sent exactly as the form holds them, for
// the admin API to refuse one it does not know.
func TestHandleBrandNewPost_SendsTheSwitchOffWhenTheFormLeavesItOut(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := newBrandingAPI()

	HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
			handlertest.WithForm(url.Values{"name": {"Spring"}, "appearance": {"auto"}, "theme": {"plum"},
				"corners": {"square"}, "font": {"Serif"}, "backgroundFit": {"tile"}})))

	assert.Equal(t, &api.CreateBrandRequest{Name: "Spring", Appearance: "auto", Theme: "plum",
		Corners: "square", Font: "Serif", BackgroundFit: "tile", HideAppName: false}, apiClient.created)
}

// Every refusal the admin API answers a brand's save with, and the field the form marks for it:
// the name for the four about the name, the appearance, theme, corners and background fit choices
// for theirs, and the font family for an unknown family and for the uploaded font without a regular
// font file (#813 decision 7). A slot naming no stored asset of its kind is marked at its own field,
// a dark logo without a logo at the logo, and a bold font file without a regular one at the regular
// font file, the field that wants a file.
var brandRefusals = []struct {
	code  string
	field string
}{
	{"handler.brand.name_required", "name"},
	{"handler.brand.name_too_long", "name"},
	{"handler.brand.name_angle_brackets", "name"},
	{"handler.brand.name_in_use", "name"},
	{"handler.brand.appearance_invalid", "appearance"},
	{"handler.brand.theme_invalid", "theme"},
	{"handler.brand.corners_invalid", "corners"},
	{"handler.brand.font_invalid", "font"},
	{"handler.brand.uploaded_font_regular_required", "font"},
	{"handler.brand.background_fit_invalid", "backgroundFit"},
	{"handler.brand.logo_asset_invalid", "logo"},
	{"handler.brand.dark_logo_asset_invalid", "darkLogo"},
	{"handler.brand.favicon_asset_invalid", "favicon"},
	{"handler.brand.background_asset_invalid", "background"},
	{"handler.brand.regular_font_asset_invalid", "regularFont"},
	{"handler.brand.bold_font_asset_invalid", "boldFont"},
	{"handler.brand.dark_logo_logo_required", "logo"},
	{"handler.brand.bold_font_regular_required", "regularFont"},
	{"INVALID_REQUEST_BODY", ""},
}

func TestHandleBrandNewPost_EachRefusalIsShownOnItsField(t *testing.T) {
	for _, tc := range brandRefusals {
		t.Run(tc.code, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()
			apiClient := newBrandingAPI()
			apiClient.writeErr = refusal(tc.code, "Not that.")
			cache := &invalidationRecorder{}

			HandleBrandNewPost(httpHelper, apiClient, cache, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
					handlertest.WithForm(url.Values{"name": {"<Spring>"}, "appearance": {"sepia"}, "theme": {"plum"},
						"corners": {"oval"}, "font": {"uploaded"}, "backgroundFit": {"stretch"}, "hideAppName": {"on"}})))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, "Not that.", bind["error"])
			assert.Equal(t, tc.field, bind["errorField"])
			assert.Equal(t, BrandForm{Name: "<Spring>", Appearance: "sepia", Theme: "plum", Corners: "oval", Font: "uploaded",
				BackgroundFit: "stretch", HideAppName: true}, bind["brand"], "with what was sent")
			assert.Equal(t, true, bind["isNew"])
			assert.Equal(t, wantThemeOptions, bind["brandThemes"])
			assert.Equal(t, wantThemeOptions[1], bind["appearanceTheme"])
			assert.Equal(t, 0, cache.invalidations, "a refused save changed nothing")
		})
	}
}

func TestHandleBrandGet_DrawsTheStoredBrand(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()

	HandleBrandGet(httpHelper, newSettingsTestStore(), newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding/4/edit", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "4")))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, false, bind["isNew"])
	stored := newBrandingAPI().brands[0]
	assert.Equal(t, BrandForm{Name: "Autumn", Appearance: "dark", Theme: "plum", Corners: "pill", Font: "serif",
		BackgroundFit: "tile", HideAppName: true, Logo: stored.Logo, Favicon: stored.Favicon, RegularFont: stored.RegularFont},
		bind["brand"], "the stored choices and slots")
	assert.Equal(t, newBrandingAPI().brands[0], bind["storedBrand"])
	assert.Equal(t, wantThemeOptions, bind["brandThemes"])
	assert.Equal(t, wantThemeOptions[1], bind["appearanceTheme"], "the appearance cards show the brand's theme")
	assert.Equal(t, false, bind["savedSuccessfully"])
	assert.Equal(t, false, bind["madeDefault"])
}

func TestHandleBrandGet_AnUnknownOrMalformedBrandIsNotFound(t *testing.T) {
	for _, id := range []string{"77", "abc"} {
		t.Run(id, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			httpHelper.On("NotFound", mock.Anything, mock.Anything).Once()

			HandleBrandGet(httpHelper, newSettingsTestStore(), newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/settings/branding/"+id+"/edit", handlertest.WithAccessToken(),
					handlertest.WithPathValue("brandId", id)))
		})
	}
}

// A save of a brand's fields, and the edit page it lands on, which says it was saved once. The kit's
// four choices are sent as the form holds them, the switch off as the form leaves it out, and each
// slot as the form holds it, by its asset's id (#813 decision 1): one kept from the stored brand, one
// replaced by an upload, one added and one removed, which the form sends empty, as an update replaces
// every field (#813 decision 10).
func TestHandleBrandPost_SavesTheBrandAndSaysSoOnItsPage(t *testing.T) {
	store := newSettingsTestStore()
	apiClient := newBrandingAPI()
	cache := &invalidationRecorder{}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	w := httptest.NewRecorder()

	HandleBrandPost(httpHelper, store, apiClient, cache, consoleBaseURL).ServeHTTP(w,
		handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "4"),
			handlertest.WithForm(withValues(slotsForm("11", "", "", "24", "25", ""), url.Values{
				"name": {" Winter "}, "appearance": {"light"}, "theme": {"blueberry"},
				"corners": {"square"}, "font": {"uploaded"}, "backgroundFit": {"contain"},
				"logoUrl": {"https://elsewhere.example/a.png"}}))))

	assert.Equal(t, int64(4), apiClient.updatedId)
	assert.Equal(t, &api.UpdateBrandRequest{Name: "Winter", Appearance: "light", Theme: "blueberry",
		Corners: "square", Font: "uploaded", BackgroundFit: "contain", HideAppName: false,
		Logo: &api.BrandAssetRef{Id: 11}, Background: &api.BrandAssetRef{Id: 24}, RegularFont: &api.BrandAssetRef{Id: 25}},
		apiClient.updated)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://console.example.test/admin/settings/branding/4/edit", w.Header().Get("Location"))
	assert.Equal(t, 1, cache.invalidations, "a saved brand may be the default, so every page is drawn again")

	bind := editPageAfter(t, store, apiClient, w)
	assert.Equal(t, true, bind["savedSuccessfully"])
	assert.Equal(t, false, bind["madeDefault"])
}

// Create attaches the files uploaded in the new brand's form, each slot by its asset's id, and sends
// an empty slot empty (#813 decision 1).
func TestHandleBrandNewPost_AttachesTheUploadedFiles(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := newBrandingAPI()

	HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
			handlertest.WithForm(withValues(slotsForm("21", "22", "23", "", "25", "26"), url.Values{
				"name": {"Spring"}, "appearance": {"auto"}, "theme": {"plum"},
				"corners": {"rounded"}, "font": {"uploaded"}, "backgroundFit": {"cover"}}))))

	assert.Equal(t, &api.CreateBrandRequest{Name: "Spring", Appearance: "auto", Theme: "plum",
		Corners: "rounded", Font: "uploaded", BackgroundFit: "cover",
		Logo: &api.BrandAssetRef{Id: 21}, DarkLogo: &api.BrandAssetRef{Id: 22}, Favicon: &api.BrandAssetRef{Id: 23},
		RegularFont: &api.BrandAssetRef{Id: 25}, BoldFont: &api.BrandAssetRef{Id: 26}}, apiClient.created)
}

// A slot holding no number, which the editor never sends, is sent as an asset no store holds, for the
// admin API to refuse at its field, rather than emptied without a word.
func TestHandleBrandNewPost_ASlotHoldingNoNumberIsSentForTheAPIToRefuse(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := newBrandingAPI()

	HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
			handlertest.WithForm(withValues(slotsForm("logo.png", "", "", "", "", ""), url.Values{
				"name": {"Spring"}, "appearance": {"auto"}, "theme": {"plum"},
				"corners": {"rounded"}, "font": {"system-ui"}, "backgroundFit": {"cover"}}))))

	require.NotNil(t, apiClient.created)
	assert.Equal(t, &api.BrandAssetRef{Id: 0}, apiClient.created.Logo)
}

// A refused form is drawn again with the files it held, each read by its id, so an upload not yet
// saved is still drawn and sent with the next Save (#813 decision 10). One the admin API no longer
// holds, swept or never stored, is drawn empty, for the refusal at its field to be answered with a new
// upload.
func TestHandleBrandWrite_ARefusedFormKeepsItsUploads(t *testing.T) {
	form := withValues(slotsForm("21", "22", "", "24", "99", "26"), url.Values{
		"name": {"Spring"}, "appearance": {"auto"}, "theme": {"plum"},
		"corners": {"rounded"}, "font": {"uploaded"}, "backgroundFit": {"tile"}})
	want := BrandForm{Name: "Spring", Appearance: "auto", Theme: "plum", Corners: "rounded", Font: "uploaded",
		BackgroundFit: "tile", Logo: &uploadedLogo, DarkLogo: &uploadedDarkLogo, Background: &uploadedBackground,
		BoldFont: &uploadedBoldFont}

	draw := map[string]func(httpHelper *handlersmocks.HttpHelper, apiClient *brandingAPI){
		"new form": func(httpHelper *handlersmocks.HttpHelper, apiClient *brandingAPI) {
			HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
					handlertest.WithForm(form)))
		},
		"brand's form": func(httpHelper *handlersmocks.HttpHelper, apiClient *brandingAPI) {
			HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(
				httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit",
					handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", "4"), handlertest.WithForm(form)))
		},
	}
	for name, drawPage := range draw {
		t.Run(name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()
			apiClient := newBrandingAPI()
			apiClient.writeErr = refusal("handler.brand.regular_font_asset_invalid", "Upload it again.")

			drawPage(httpHelper, apiClient)

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, "regularFont", bind["errorField"])
			assert.Equal(t, want, bind["brand"])
		})
	}
}

// A refused form whose file cannot be read for a reason other than its absence answers the page that
// says why, as any other failed read does.
func TestHandleBrandNewPost_AFailedReadOfARefusedFormsFileIsAnswered(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()
	apiClient := newBrandingAPI()
	apiClient.writeErr = refusal("handler.brand.name_required", "Not that.")
	apiClient.assets = nil
	apiClient.assetErr = &apiclient.APIError{Code: "INTERNAL_SERVER_ERROR", Message: "on fire", StatusCode: http.StatusInternalServerError}

	HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
			handlertest.WithForm(withValues(slotsForm("21", "", "", "", "", ""), url.Values{"name": {""}}))))

	httpHelper.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestHandleBrandPost_EachRefusalIsShownOnItsField(t *testing.T) {
	for _, tc := range brandRefusals {
		t.Run(tc.code, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()
			apiClient := newBrandingAPI()
			apiClient.writeErr = refusal(tc.code, "Not that.")
			cache := &invalidationRecorder{}

			HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, cache, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit", handlertest.WithAccessToken(),
					handlertest.WithPathValue("brandId", "4"),
					handlertest.WithForm(url.Values{"name": {"Default"}, "appearance": {"light"}, "theme": {"guava"},
						"corners": {"rounded"}, "font": {"geometric"}, "backgroundFit": {"cover"}})))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, "Not that.", bind["error"])
			assert.Equal(t, tc.field, bind["errorField"])
			assert.Equal(t, BrandForm{Name: "Default", Appearance: "light", Theme: "guava", Corners: "rounded", Font: "geometric",
				BackgroundFit: "cover"}, bind["brand"], "with what was sent")
			assert.Equal(t, "Autumn", bind["storedBrand"].(api.BrandResponse).Name, "the title keeps the stored name")
			assert.Equal(t, false, bind["isNew"])
			assert.Equal(t, wantThemeOptions, bind["brandThemes"])
			assert.Equal(t, wantThemeOptions[0], bind["appearanceTheme"], "a theme the server does not list shows the first")
			assert.Equal(t, 0, cache.invalidations, "a refused save changed nothing")
		})
	}
}

// Make default moves the default, draws every page again, and lands on the brand's page saying so.
func TestHandleBrandMakeDefaultPost_MovesTheDefaultAndSaysSoOnTheBrandsPage(t *testing.T) {
	store := newSettingsTestStore()
	apiClient := newBrandingAPI()
	cache := &invalidationRecorder{}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	w := httptest.NewRecorder()

	HandleBrandMakeDefaultPost(httpHelper, store, apiClient, cache, consoleBaseURL).ServeHTTP(w,
		handlertest.Request(http.MethodPost, "/admin/settings/branding/4/make-default", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "4")))

	assert.Equal(t, int64(4), apiClient.madeDefault)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://console.example.test/admin/settings/branding/4/edit", w.Header().Get("Location"))
	assert.Equal(t, 1, cache.invalidations)

	bind := editPageAfter(t, store, apiClient, w)
	assert.Equal(t, true, bind["madeDefault"])
	assert.Equal(t, false, bind["savedSuccessfully"])
}

func TestHandleBrandMakeDefaultPost_AnUnknownBrandIsNotFoundAndChangesNothing(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	httpHelper.On("NotFound", mock.Anything, mock.Anything).Once()
	apiClient := newBrandingAPI()
	apiClient.writeErr = &apiclient.APIError{Code: "NOT_FOUND", Message: "Brand not found", StatusCode: http.StatusNotFound}
	cache := &invalidationRecorder{}

	HandleBrandMakeDefaultPost(httpHelper, newSettingsTestStore(), apiClient, cache, consoleBaseURL).ServeHTTP(
		httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/branding/77/make-default",
			handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", "77")))

	assert.Equal(t, 0, cache.invalidations)
}

func TestHandleBrandDeleteGet_DrawsTheBrandInWords(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_delete.html").Once()

	HandleBrandDeleteGet(httpHelper, newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding/5/delete", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "5")))

	assert.Equal(t, BrandRow{
		BrandResponse:  api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true, ClientCount: 3},
		AppearanceName: "Automatic", ThemeName: "Blueberry",
	}, handlertest.Bind(t, httpHelper)["brand"])
}

// A brand's page says how many clients it draws, in a sentence for none, one and more (#812
// decision 3); a refused save of the page says it too.
func TestHandleBrandGet_SaysHowManyClientsUseTheBrand(t *testing.T) {
	for id, want := range map[string]string{
		"4": "2 clients use this brand.",
		"5": "3 clients use this brand.",
		"6": "1 client uses this brand.",
		"7": "No client uses this brand.",
	} {
		t.Run(id, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()

			HandleBrandGet(httpHelper, newSettingsTestStore(), newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/settings/branding/"+id+"/edit", handlertest.WithAccessToken(),
					handlertest.WithPathValue("brandId", id)))

			assert.Equal(t, want, handlertest.Bind(t, httpHelper)["clientsNote"])
		})
	}

	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()
	apiClient := newBrandingAPI()
	apiClient.writeErr = refusal("handler.brand.name_in_use", "Not that.")
	HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(
		httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/branding/6/edit",
			handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", "6"),
			handlertest.WithForm(url.Values{"name": {"Autumn"}, "appearance": {"auto"}, "theme": {"plum"}})))
	assert.Equal(t, "1 client uses this brand.", handlertest.Bind(t, httpHelper)["clientsNote"], "a refused save")
}

// The delete confirmation says how many clients use the brand and that they will move to the
// default brand, which it names, or that no client uses it (#812 decision 3). A refused deletion
// is drawn again saying it too.
func TestHandleBrandDeleteGet_SaysWhereTheBrandsClientsWillMove(t *testing.T) {
	for id, want := range map[string]string{
		"4": "2 clients use it. They will move to the default brand, Default.",
		"6": "1 client uses it. It will move to the default brand, Default.",
		"7": "No client uses it, so no page will change.",
	} {
		t.Run(id, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_delete.html").Once()

			HandleBrandDeleteGet(httpHelper, newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/settings/branding/"+id+"/delete", handlertest.WithAccessToken(),
					handlertest.WithPathValue("brandId", id)))

			assert.Equal(t, want, handlertest.Bind(t, httpHelper)["clientsNote"])
		})
	}

	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_delete.html").Once()
	HandleBrandDeletePost(httpHelper, newBrandingAPI(), &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/4/delete", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "4"), handlertest.WithForm(url.Values{"name": {"autumn"}})))
	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, "That isn't this brand's name. Type it as shown above.", bind["error"])
	assert.Equal(t, "2 clients use it. They will move to the default brand, Default.", bind["clientsNote"], "a refused deletion")
}

// The default brand named is the one the auth server marks, not the brand being deleted or the
// first listed.
func TestHandleBrandDeleteGet_NamesTheDefaultTheServerMarks(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_delete.html").Once()
	apiClient := newBrandingAPI()
	apiClient.brands[1].IsDefault = false
	apiClient.brands[3].IsDefault = true

	HandleBrandDeleteGet(httpHelper, apiClient).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding/4/delete", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "4")))

	assert.Equal(t, "2 clients use it. They will move to the default brand, Unused.", handlertest.Bind(t, httpHelper)["clientsNote"])
}

func TestHandleBrandDeletePost_DeletesTheBrandWhoseNameIsTyped(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := newBrandingAPI()
	cache := &invalidationRecorder{}
	w := httptest.NewRecorder()

	HandleBrandDeletePost(httpHelper, apiClient, cache, consoleBaseURL).ServeHTTP(w,
		handlertest.Request(http.MethodPost, "/admin/settings/branding/4/delete", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "4"), handlertest.WithForm(url.Values{"name": {"Autumn"}})))

	assert.Equal(t, int64(4), apiClient.deletedId)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://console.example.test/admin/settings/branding", w.Header().Get("Location"))
	assert.Equal(t, 1, cache.invalidations)
}

// The confirmation is the brand's name, typed exactly; anything else is refused before the API is
// asked. The default's refusal is the auth server's, which holds the rule under its lock.
func TestHandleBrandDeletePost_Refusals(t *testing.T) {
	testCases := []struct {
		name     string
		typed    string
		brandId  string
		writeErr error
		message  string
		deleted  int64
	}{
		{name: "nothing typed", typed: "", brandId: "4", message: "Type the brand's name to confirm."},
		{name: "another name", typed: "autumn", brandId: "4", message: "That isn't this brand's name. Type it as shown above."},
		{name: "the default", typed: "Default", brandId: "5", deleted: 5,
			writeErr: refusal("handler.brand.default_delete_not_allowed", "The default brand cannot be deleted."),
			message:  "The default brand cannot be deleted."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_delete.html").Once()
			apiClient := newBrandingAPI()
			apiClient.writeErr = tc.writeErr
			cache := &invalidationRecorder{}

			HandleBrandDeletePost(httpHelper, apiClient, cache, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodPost, "/admin/settings/branding/"+tc.brandId+"/delete", handlertest.WithAccessToken(),
					handlertest.WithPathValue("brandId", tc.brandId), handlertest.WithForm(url.Values{"name": {tc.typed}})))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, tc.message, bind["error"])
			assert.Equal(t, tc.deleted, apiClient.deletedId)
			assert.Equal(t, 0, cache.invalidations)
		})
	}
}

// The brand editor hands its preview script every listed theme's light and dark palette, in the
// auth server's order, as the page's palettes data block encodes them: the new form, a stored
// brand's page and a refused form alike, whatever theme the form holds.
func TestBrandEditor_HandsThePreviewEveryThemesPalettes(t *testing.T) {
	const want = `[{"key":"blueberry","light":{"canvas":"#000001","surface":"#000002"},"dark":{"canvas":"#000003","surface":"#000004"}},` +
		`{"key":"plum","light":{"canvas":"#000011","surface":"#000012"},"dark":{"canvas":"#000013","surface":"#000014"}}]`

	draw := map[string]func(httpHelper *handlersmocks.HttpHelper){
		"new form": func(httpHelper *handlersmocks.HttpHelper) {
			HandleBrandNewGet(httpHelper, newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/settings/branding/new", handlertest.WithAccessToken()))
		},
		"stored brand": func(httpHelper *handlersmocks.HttpHelper) {
			HandleBrandGet(httpHelper, newSettingsTestStore(), newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/settings/branding/4/edit", handlertest.WithAccessToken(),
					handlertest.WithPathValue("brandId", "4")))
		},
		"refused form": func(httpHelper *handlersmocks.HttpHelper) {
			apiClient := newBrandingAPI()
			apiClient.writeErr = refusal("handler.brand.theme_invalid", "Not that.")
			HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(
				httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit",
					handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", "4"),
					handlertest.WithForm(url.Values{"name": {"Autumn"}, "appearance": {"auto"}, "theme": {"guava"}})))
		},
	}
	for name, drawPage := range draw {
		t.Run(name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()

			drawPage(httpHelper)

			encoded, err := json.Marshal(handlertest.Bind(t, httpHelper)["brandThemes"])
			require.NoError(t, err)
			assert.JSONEq(t, want, string(encoded))
		})
	}
}

// The brand editor hands its preview script what each corner shape and font family draws, so the
// sample takes them as they are picked (#813): the radii of square and pill and the font-family list
// of each family but System UI, the uploaded font's followed by System UI. Rounded and System UI are
// today's look, the console's own, so they draw nothing. It also hands the weights each file of an
// uploaded font draws with a bold file, and how a background is laid out at each fit. The values are
// the auth server's stylesheet's, spelt out here.
func TestBrandEditor_HandsThePreviewWhatEachCornerShapeAndFamilyDraws(t *testing.T) {
	const want = `{"corners":{` +
		`"square":{"control":"0","panel":"0"},` +
		`"pill":{"control":"9999px","panel":"1.5rem"}},` +
		`"fonts":{` +
		`"humanist":"Seravek, 'Gill Sans Nova', Ubuntu, Calibri, 'DejaVu Sans', source-sans-pro, sans-serif",` +
		`"geometric":"Avenir, Montserrat, Corbel, 'URW Gothic', source-sans-pro, sans-serif",` +
		`"serif":"Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif",` +
		`"neo-grotesque":"Inter, Roboto, 'Helvetica Neue', 'Arial Nova', 'Nimbus Sans', Arial, sans-serif",` +
		`"rounded":"ui-rounded, 'Hiragino Maru Gothic ProN', Quicksand, Comfortaa, Manjari, 'Arial Rounded MT', 'Arial Rounded MT Bold', Calibri, source-sans-pro, sans-serif",` +
		`"uploaded":"\"brand-font\", -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', 'Noto Sans', Arial, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji'"},` +
		`"uploadedFamily":"brand-font",` +
		`"fontWeights":{"regular":"1 500","bold":"501 1000"},` +
		`"backgrounds":{` +
		`"cover":{"size":"cover","position":"center","repeat":"no-repeat"},` +
		`"contain":{"size":"contain","position":"center","repeat":"no-repeat"},` +
		`"tile":{"size":"","position":"","repeat":"repeat"}}}`

	draw := map[string]func(httpHelper *handlersmocks.HttpHelper){
		"new form": func(httpHelper *handlersmocks.HttpHelper) {
			HandleBrandNewGet(httpHelper, newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/settings/branding/new", handlertest.WithAccessToken()))
		},
		"refused new form": func(httpHelper *handlersmocks.HttpHelper) {
			apiClient := newBrandingAPI()
			apiClient.writeErr = refusal("handler.brand.corners_invalid", "Not that.")
			HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
					handlertest.WithForm(url.Values{"name": {"Spring"}, "appearance": {"auto"}, "theme": {"plum"}})))
		},
		"stored brand": func(httpHelper *handlersmocks.HttpHelper) {
			HandleBrandGet(httpHelper, newSettingsTestStore(), newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
				handlertest.Request(http.MethodGet, "/admin/settings/branding/4/edit", handlertest.WithAccessToken(),
					handlertest.WithPathValue("brandId", "4")))
		},
		"refused form": func(httpHelper *handlersmocks.HttpHelper) {
			apiClient := newBrandingAPI()
			apiClient.writeErr = refusal("handler.brand.font_invalid", "Not that.")
			HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(
				httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit",
					handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", "4"),
					handlertest.WithForm(url.Values{"name": {"Autumn"}, "appearance": {"auto"}, "theme": {"plum"}, "font": {"comic"}})))
		},
	}
	for name, drawPage := range draw {
		t.Run(name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()

			drawPage(httpHelper)

			encoded, err := json.Marshal(handlertest.Bind(t, httpHelper)["brandKitStyles"])
			require.NoError(t, err)
			assert.JSONEq(t, want, string(encoded))
		})
	}
}

// editPageAfter draws the brand's edit page in the browser the redirect w answered went back to,
// carrying its session cookie, and answers what the page was drawn with.
func editPageAfter(t *testing.T, store sessionstore.Store, apiClient *brandingAPI, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()
	req := handlertest.Request(http.MethodGet, "/admin/settings/branding/4/edit", handlertest.WithAccessToken(),
		handlertest.WithPathValue("brandId", "4"))
	for _, cookie := range w.Result().Cookies() {
		req.AddCookie(cookie)
	}
	HandleBrandGet(httpHelper, store, apiClient).ServeHTTP(httptest.NewRecorder(), req)
	return handlertest.Bind(t, httpHelper)
}
