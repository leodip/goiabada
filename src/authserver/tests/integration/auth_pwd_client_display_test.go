package integrationtests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func TestAuthPwd_ClientDisplay_ShowDisplayName_WithValue(t *testing.T) {
	// Create client with display name enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		DisplayName:      "My Awesome Application",
		ShowDisplayName:  true,
		ShowLogo:         false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
		ConsentRequired:  false,
		DefaultAcrLevel:  enums.AcrLevel1,
	})

	// Create redirect URI
	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Navigate to password screen
	httpClient := createHttpClient(t)
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert display name is shown (not client identifier)
	assertClientNameInHTML(t, doc, "My Awesome Application")

	// Assert no logo/description/URL
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthPwd_ClientDisplay_ShowDisplayName_Empty(t *testing.T) {
	// Create client with display name enabled but empty
	clientId := "test-app-" + gofakeit.LetterN(8)
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: clientId,
		DisplayName:      "", // Empty display name
		ShowDisplayName:  true,
		ShowLogo:         false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Should fall back to client identifier
	assertClientNameInHTML(t, doc, clientId)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthPwd_ClientDisplay_HideDisplayName(t *testing.T) {
	// Create client with display name set but ShowDisplayName=false
	clientId := "test-app-" + gofakeit.LetterN(8)
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: clientId,
		DisplayName:      "My Awesome Application",
		ShowDisplayName:  false, // Hidden
		ShowLogo:         false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Should show client identifier, not display name
	assertClientNameInHTML(t, doc, clientId)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthPwd_ClientDisplay_ShowLogo_WithLogo(t *testing.T) {
	// Create client with logo enabled and uploaded
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		ShowLogo:         true,
		UploadLogo:       true, // Upload logo
		ShowDisplayName:  false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Logo should be visible
	assertClientNameInHTML(t, doc, client.ClientIdentifier)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, true)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthPwd_ClientDisplay_ShowLogo_NoLogo(t *testing.T) {
	// Create client with logo enabled but not uploaded
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		ShowLogo:         true,
		UploadLogo:       false, // No logo uploaded
		ShowDisplayName:  false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Logo should NOT be visible (no logo uploaded)
	assertClientNameInHTML(t, doc, client.ClientIdentifier)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthPwd_ClientDisplay_HideLogo_WithLogo(t *testing.T) {
	// Create client with logo uploaded but ShowLogo=false
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		ShowLogo:         false, // Hidden
		UploadLogo:       true,  // Logo exists
		ShowDisplayName:  false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Logo should NOT be visible (ShowLogo=false)
	assertClientNameInHTML(t, doc, client.ClientIdentifier)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthPwd_ClientDisplay_ShowDescription_WithValue(t *testing.T) {
	// Create client with description enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		Description:      "The best app for testing OAuth flows",
		ShowDescription:  true,
		ShowLogo:         false,
		ShowDisplayName:  false,
		ShowWebsiteURL:   false,
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Description should be visible
	assertClientNameInHTML(t, doc, client.ClientIdentifier)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", true)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthPwd_ClientDisplay_ShowDescription_Empty(t *testing.T) {
	// Create client with description enabled but empty
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		Description:      "", // Empty
		ShowDescription:  true,
		ShowLogo:         false,
		ShowDisplayName:  false,
		ShowWebsiteURL:   false,
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Description should NOT be visible (empty)
	assertClientNameInHTML(t, doc, client.ClientIdentifier)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthPwd_ClientDisplay_HideDescription(t *testing.T) {
	// Create client with description set but ShowDescription=false
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		Description:      "The best app for testing OAuth flows",
		ShowDescription:  false, // Hidden
		ShowLogo:         false,
		ShowDisplayName:  false,
		ShowWebsiteURL:   false,
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Description should NOT be visible (ShowDescription=false)
	assertClientNameInHTML(t, doc, client.ClientIdentifier)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthPwd_ClientDisplay_ShowWebsiteUrl_WithValue(t *testing.T) {
	// Create client with website URL enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		WebsiteURL:       "https://example.com",
		ShowWebsiteURL:   true,
		ShowLogo:         false,
		ShowDisplayName:  false,
		ShowDescription:  false,
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Website URL should be visible
	assertClientNameInHTML(t, doc, client.ClientIdentifier)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "https://example.com", true)
}

func TestAuthPwd_ClientDisplay_ShowWebsiteUrl_Empty(t *testing.T) {
	// Create client with website URL enabled but empty
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		WebsiteURL:       "", // Empty
		ShowWebsiteURL:   true,
		ShowLogo:         false,
		ShowDisplayName:  false,
		ShowDescription:  false,
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Website URL should NOT be visible (empty)
	assertClientNameInHTML(t, doc, client.ClientIdentifier)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthPwd_ClientDisplay_HideWebsiteUrl(t *testing.T) {
	// Create client with website URL set but ShowWebsiteURL=false
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		WebsiteURL:       "https://example.com",
		ShowWebsiteURL:   false, // Hidden
		ShowLogo:         false,
		ShowDisplayName:  false,
		ShowDescription:  false,
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Website URL should NOT be visible (ShowWebsiteURL=false)
	assertClientNameInHTML(t, doc, client.ClientIdentifier)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "https://example.com", false)
}

func TestAuthPwd_ClientDisplay_AllEnabled(t *testing.T) {
	// Create client with all display settings enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		DisplayName:      "My Awesome Application",
		Description:      "The best app for testing OAuth flows",
		WebsiteURL:       "https://example.com",
		ShowLogo:         true,
		ShowDisplayName:  true,
		ShowDescription:  true,
		ShowWebsiteURL:   true,
		UploadLogo:       true, // Upload logo
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// All elements should be visible
	assertClientNameInHTML(t, doc, "My Awesome Application")
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, true)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", true)
	assertClientWebsiteUrlInHTML(t, doc, "https://example.com", true)
}

func TestAuthPwd_ClientDisplay_AllDisabled(t *testing.T) {
	// Create client with all display settings disabled
	clientId := "test-app-" + gofakeit.LetterN(8)
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: clientId,
		DisplayName:      "My Awesome Application",
		Description:      "The best app for testing OAuth flows",
		WebsiteURL:       "https://example.com",
		ShowLogo:         false,
		ShowDisplayName:  false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
		UploadLogo:       true, // Logo exists but hidden
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
	resp := navigateToPasswordScreen(t, httpClient, client, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	doc := parseHTMLResponse(t, resp)

	// Only client identifier should be visible
	assertClientNameInHTML(t, doc, clientId)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", false)
	assertClientWebsiteUrlInHTML(t, doc, "https://example.com", false)
}
