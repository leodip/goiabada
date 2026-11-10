package adminsettingshandlers

import (
	"context"
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
			{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum"},
			{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true},
		},
		themes: []api.BrandThemeResponse{testBlueberry, testPlum},
	}
}

func refusal(code, message string) error {
	return &apiclient.APIError{Code: code, Message: message, StatusCode: http.StatusBadRequest}
}

func TestHandleBrandingGet_ListsTheBrandsInTheServersOrderWithTheirLookInWords(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding.html").Once()

	HandleBrandingGet(httpHelper, newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding", handlertest.WithAccessToken()))

	assert.Equal(t, []BrandRow{
		{BrandResponse: api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum"},
			AppearanceName: "Dark", ThemeName: "Plum"},
		{BrandResponse: api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true},
			AppearanceName: "Automatic", ThemeName: "Blueberry"},
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

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, true, bind["isNew"])
	assert.Equal(t, BrandForm{Appearance: "auto", Theme: "blueberry"}, bind["brand"])
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
			handlertest.WithForm(url.Values{"name": {"  Spring  "}, "appearance": {"dark"}, "theme": {"plum"}})))

	assert.Equal(t, &api.CreateBrandRequest{Name: "Spring", Appearance: "dark", Theme: "plum"}, apiClient.created)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://console.example.test/admin/settings/branding", w.Header().Get("Location"))
	assert.Equal(t, 1, cache.invalidations)
}

// Every refusal the admin API answers a brand's save with, and the field the form marks for it:
// the name for the four about the name, and the appearance and theme choices for theirs.
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
					handlertest.WithForm(url.Values{"name": {"<Spring>"}, "appearance": {"sepia"}, "theme": {"plum"}})))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, "Not that.", bind["error"])
			assert.Equal(t, tc.field, bind["errorField"])
			assert.Equal(t, BrandForm{Name: "<Spring>", Appearance: "sepia", Theme: "plum"}, bind["brand"], "with what was sent")
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
	assert.Equal(t, BrandForm{Name: "Autumn", Appearance: "dark", Theme: "plum"}, bind["brand"])
	assert.Equal(t, api.BrandResponse{Id: 4, Name: "Autumn", Appearance: "dark", Theme: "plum"}, bind["storedBrand"])
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

// A save of a brand's three fields, and the edit page it lands on, which says it was saved once.
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
			handlertest.WithForm(url.Values{"name": {" Winter "}, "appearance": {"light"}, "theme": {"blueberry"}})))

	assert.Equal(t, int64(4), apiClient.updatedId)
	assert.Equal(t, &api.UpdateBrandRequest{Name: "Winter", Appearance: "light", Theme: "blueberry"}, apiClient.updated)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://console.example.test/admin/settings/branding/4/edit", w.Header().Get("Location"))
	assert.Equal(t, 1, cache.invalidations, "a saved brand may be the default, so every page is drawn again")

	bind := editPageAfter(t, store, apiClient, w)
	assert.Equal(t, true, bind["savedSuccessfully"])
	assert.Equal(t, false, bind["madeDefault"])
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
					handlertest.WithForm(url.Values{"name": {"Default"}, "appearance": {"light"}, "theme": {"guava"}})))

			bind := handlertest.Bind(t, httpHelper)
			assert.Equal(t, "Not that.", bind["error"])
			assert.Equal(t, tc.field, bind["errorField"])
			assert.Equal(t, BrandForm{Name: "Default", Appearance: "light", Theme: "guava"}, bind["brand"], "with what was sent")
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
		BrandResponse:  api.BrandResponse{Id: 5, Name: "Default", Appearance: "auto", Theme: "blueberry", IsDefault: true},
		AppearanceName: "Automatic", ThemeName: "Blueberry",
	}, handlertest.Bind(t, httpHelper)["brand"])
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
