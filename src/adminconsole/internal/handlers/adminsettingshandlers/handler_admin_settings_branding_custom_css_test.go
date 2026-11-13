package adminsettingshandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The brand editor has no custom CSS field yet, and an update replaces every field of a brand, so a
// save sends back the custom CSS the admin API answered for the brand, unchanged, rather than
// erasing it (#816).
func TestHandleBrandPost_SendsBackTheStoredCustomCSS(t *testing.T) {
	const css = "body[data-page=\"sign-in\"] .auth-card {\n  border: 2px solid var(--color-brand);\n}\n"
	apiClient := newBrandingAPI()
	apiClient.brands[0].CustomCss = css
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)

	HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(
		httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "4"),
			handlertest.WithForm(url.Values{"name": {"Autumn"}, "appearance": {"dark"}, "theme": {"plum"},
				"corners": {"pill"}, "font": {"serif"}, "backgroundFit": {"tile"},
				"customCss": {".auth-card { display: none; }"}})))

	require.NotNil(t, apiClient.updated)
	assert.Equal(t, css, apiClient.updated.CustomCss, "the stored CSS, not a form value the editor does not draw")
}
