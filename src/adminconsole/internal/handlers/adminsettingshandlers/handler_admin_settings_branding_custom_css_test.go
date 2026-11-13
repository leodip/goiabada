package adminsettingshandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
)

// The editor's Custom CSS field (#816 decision 4): the brand's custom CSS, sent to the admin API as
// typed, which checks it and stores it, and refused at the field with the sentence naming its line.

// storedCustomCSS is the custom CSS the brand Autumn is stored with in these tests.
const storedCustomCSS = "body[data-page=\"sign-in\"] .auth-card {\n  border: 2px solid var(--color-brand);\n}\n"

// A stored brand's page holds its custom CSS as the admin API answered it.
func TestHandleBrandGet_DrawsTheStoredCustomCSS(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()
	apiClient := newBrandingAPI()
	apiClient.brands[0].CustomCss = storedCustomCSS

	HandleBrandGet(httpHelper, newSettingsTestStore(), apiClient).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding/4/edit", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "4")))

	assert.Equal(t, storedCustomCSS, handlertest.Bind(t, httpHelper)["brand"].(BrandForm).CustomCss)
}

// A new brand's CSS is sent exactly as the browser sent it, its spaces and CRLF line endings included:
// what is stored is what was written, with line endings made uniform by the auth server, so the
// console rewrites nothing.
func TestHandleBrandNewPost_SendsTheCustomCSSAsTyped(t *testing.T) {
	const typed = "  .auth-card {\r\n  color: red;\r\n}\r\n\r\n"
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := newBrandingAPI()

	HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
			handlertest.WithForm(footerForm(url.Values{"customCss": {typed}}))))

	require.NotNil(t, apiClient.created)
	assert.Equal(t, typed, apiClient.created.CustomCss)
}

// A save sends the CSS the form holds, not the stored one: changed, it replaces it, and emptied, it
// clears it, as an update replaces every field of a brand.
func TestHandleBrandPost_SendsTheCustomCSSTheFormHolds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		typed string
	}{
		{"changed", ".auth-title {\n  font-size: 2rem;\n}\n"},
		{"emptied", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			apiClient := newBrandingAPI()
			apiClient.brands[0].CustomCss = storedCustomCSS

			HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(
				httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit",
					handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", "4"),
					handlertest.WithForm(footerForm(url.Values{"customCss": {tc.typed}}))))

			require.NotNil(t, apiClient.updated)
			assert.Equal(t, tc.typed, apiClient.updated.CustomCss)
		})
	}
}

// Each of the five refusals of custom CSS is shown at the field, with the admin API's sentence, which
// names the line, and the form is drawn again with the CSS as it was typed, on the new form and on a
// brand's.
func TestHandleBrandWrite_EachCustomCSSRefusalIsShownAtTheField(t *testing.T) {
	const typed = ".auth-card {\r\n  color: red;\r\n}\r\n@import \"theme.css\";\r\n"
	refusals := []error{
		refusalAt("handler.brand.custom_css_too_large", "The custom CSS cannot exceed 65536 bytes.", "/customCss"),
		refusalAt("handler.brand.custom_css_import", "Line 4 of the custom CSS has an @import. Custom CSS cannot load another stylesheet.", "/customCss"),
		refusalAt("handler.brand.custom_css_url", "Line 4 of the custom CSS has a URL that is not a data: image. Custom CSS can hold no other URL.", "/customCss"),
		refusalAt("handler.brand.custom_css_function", "Line 4 of the custom CSS uses src(), image() or image-set(). Write a data: image in url() instead.", "/customCss"),
		refusalAt("handler.brand.custom_css_malformed", "Line 4 of the custom CSS cannot be read as CSS: a comment, a string or a url() is not closed or is written wrongly.", "/customCss"),
	}
	for _, err := range refusals {
		var apiErr *apiclient.APIError
		require.ErrorAs(t, err, &apiErr)
		t.Run(apiErr.Code, func(t *testing.T) {
			for name, post := range map[string]func(httpHelper *handlersmocks.HttpHelper, apiClient *brandingAPI){
				"new form": func(httpHelper *handlersmocks.HttpHelper, apiClient *brandingAPI) {
					HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
						handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
							handlertest.WithForm(footerForm(url.Values{"customCss": {typed}}))))
				},
				"brand's form": func(httpHelper *handlersmocks.HttpHelper, apiClient *brandingAPI) {
					HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(
						httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit",
							handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", "4"),
							handlertest.WithForm(footerForm(url.Values{"customCss": {typed}}))))
				},
			} {
				t.Run(name, func(t *testing.T) {
					httpHelper := handlersmocks.NewHttpHelper(t)
					handlertest.RefuseInternalServerError(t, httpHelper)
					handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()
					apiClient := newBrandingAPI()
					apiClient.brands[0].CustomCss = storedCustomCSS
					apiClient.writeErr = err

					post(httpHelper, apiClient)

					bind := handlertest.Bind(t, httpHelper)
					assert.Equal(t, "customCss", bind["errorField"])
					assert.Equal(t, apiErr.Message, bind["error"])
					assert.Equal(t, typed, bind["brand"].(BrandForm).CustomCss, "the CSS as typed, not the stored one")
				})
			}
		})
	}
}
