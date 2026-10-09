package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthPwd_UILocales_PreservedAcrossFlow is the canary for the multi-step
// localization regression: an OIDC ui_locales hint passed on /auth/authorize
// must survive the redirect chain through /auth/level1 and land on the
// rendered /auth/pwd page.
//
// We assert the rendered HTML contains a pt-BR string ("Entrar") rather than
// its English counterpart ("Sign in") — both are present in the catalog, so
// failing this test means the locale was lost somewhere in the redirect chain
// (likely AuthContext.UILocales not being read by the global locale middleware,
// or the form-body capture not being persisted on POST authorize).
func TestAuthPwd_UILocales_PreservedAcrossFlow(t *testing.T) {
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-uiloc-" + fake.LetterN(8),
		DisplayName:      "Test app",
		ShowDisplayName:  true,
		ConsentRequired:  false,
		DefaultAcrLevel:  record.AcrLevel1,
	})

	redirectUri := &record.RedirectURI{
		ClientId: client.Id,
		URI:      fake.URL(),
	}
	err := database.CreateRedirectURI(context.Background(), nil, redirectUri)
	require.NoError(t, err)

	httpClient := createHttpClient(t)

	// Same flow as navigateToPasswordScreen but with ui_locales=pt-BR.
	resp := navigateToPasswordScreenWithUILocales(t, httpClient, client, redirectUri.URI, "pt-BR")
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)
	body := doc.Find("body").Text()

	// The sign-in button text in the pt-BR stub is "Entrar"; the English one is "Sign in".
	// If ui_locales is being honored end-to-end, the pt-BR string is present
	// and the English one is not.
	assert.Contains(t, body, "Entrar",
		"expected pt-BR login button text 'Entrar' on /auth/pwd; ui_locales did not survive the multi-step flow")
	assert.NotContains(t, body, "Sign in",
		"expected English string 'Sign in' to be absent on /auth/pwd when ui_locales=pt-BR is active")
}

// TestAuthPwd_UILocales_EnglishSaysSignIn is the English twin: the password
// page's title and button say "Sign in", the glossary's verb (#519), and never
// "Login", which they said before.
func TestAuthPwd_UILocales_EnglishSaysSignIn(t *testing.T) {
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-uiloc-" + fake.LetterN(8),
		DisplayName:      "Test app",
		ShowDisplayName:  true,
		ConsentRequired:  false,
		DefaultAcrLevel:  record.AcrLevel1,
	})

	redirectUri := &record.RedirectURI{
		ClientId: client.Id,
		URI:      fake.URL(),
	}
	err := database.CreateRedirectURI(context.Background(), nil, redirectUri)
	require.NoError(t, err)

	httpClient := createHttpClient(t)

	resp := navigateToPasswordScreenWithUILocales(t, httpClient, client, redirectUri.URI, "en")
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)
	assert.Equal(t, "Sign in", strings.TrimSpace(doc.Find("h2").Text()))
	assert.Equal(t, "Sign in", strings.TrimSpace(doc.Find("form button.btn-primary").Text()))
	assert.NotContains(t, doc.Find("body").Text(), "Login",
		"expected no 'Login' on the English /auth/pwd page")
}
