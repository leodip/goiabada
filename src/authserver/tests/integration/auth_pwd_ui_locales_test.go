package integrationtests

import (
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAuthPwd_UILocales_PreservedAcrossFlow is the canary for the multi-step
// localization regression: an OIDC ui_locales hint passed on /auth/authorize
// must survive the redirect chain through /auth/level1 and land on the
// rendered /auth/pwd page.
//
// We assert the rendered HTML contains a pt-BR string ("Entrar") rather than
// its English counterpart ("Login") — both are present in the catalog, so
// failing this test means the locale was lost somewhere in the redirect chain
// (likely AuthContext.UILocales not being read by the global locale middleware,
// or the form-body capture not being persisted on POST authorize).
func TestAuthPwd_UILocales_PreservedAcrossFlow(t *testing.T) {
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-uiloc-" + gofakeit.LetterN(8),
		DisplayName:      "Test app",
		ShowDisplayName:  true,
		ConsentRequired:  false,
		DefaultAcrLevel:  enums.AcrLevel1,
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)

	// Same flow as navigateToPasswordScreen but with ui_locales=pt-BR.
	resp := navigateToPasswordScreenWithUILocales(t, httpClient, client, redirectUri.URI, "pt-BR")
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)
	body := doc.Find("body").Text()

	// The login button text in the pt-BR stub is "Entrar"; the English one is "Login".
	// If ui_locales is being honored end-to-end, the pt-BR string is present
	// and the English one is not.
	assert.True(t, strings.Contains(body, "Entrar"),
		"expected pt-BR login button text 'Entrar' on /auth/pwd; ui_locales did not survive the multi-step flow")
	assert.False(t, strings.Contains(body, "Login"),
		"expected English string 'Login' to be absent on /auth/pwd when ui_locales=pt-BR is active")
}
