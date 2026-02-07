package integrationtests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func TestConsent_ClientDisplay_ShowDisplayName(t *testing.T) {
	// Create client with display name enabled and consent required
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		DisplayName:      "My Awesome Application",
		ShowDisplayName:  true,
		ShowLogo:         false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
		ConsentRequired:  true, // Consent required
		DefaultAcrLevel:  enums.AcrLevel1,
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create user
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Navigate to consent screen
	httpClient := createHttpClient(t)
	resp := navigateToConsentScreen(t, httpClient, client, user, password, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert display name is shown on consent screen
	assertClientNameInHTML(t, doc, "My Awesome Application")
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestConsent_ClientDisplay_ShowLogo_WithLogo(t *testing.T) {
	// Create client with logo enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		ShowLogo:         true,
		UploadLogo:       true,
		ShowDisplayName:  false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
		ConsentRequired:  true,
		DefaultAcrLevel:  enums.AcrLevel1,
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create user
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Navigate to consent screen
	httpClient := createHttpClient(t)
	resp := navigateToConsentScreen(t, httpClient, client, user, password, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert logo is visible on consent screen
	assertClientNameInHTML(t, doc, client.ClientIdentifier)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, true)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestConsent_ClientDisplay_ShowDescription(t *testing.T) {
	// Create client with description enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		Description:      "The best app for testing OAuth flows",
		ShowDescription:  true,
		ShowLogo:         false,
		ShowDisplayName:  false,
		ShowWebsiteURL:   false,
		ConsentRequired:  true,
		DefaultAcrLevel:  enums.AcrLevel1,
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create user
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Navigate to consent screen
	httpClient := createHttpClient(t)
	resp := navigateToConsentScreen(t, httpClient, client, user, password, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert description is visible on consent screen
	assertClientNameInHTML(t, doc, client.ClientIdentifier)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", true)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestConsent_ClientDisplay_AllEnabled(t *testing.T) {
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
		UploadLogo:       true,
		ConsentRequired:  true,
		DefaultAcrLevel:  enums.AcrLevel1,
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create user
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Navigate to consent screen
	httpClient := createHttpClient(t)
	resp := navigateToConsentScreen(t, httpClient, client, user, password, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert all elements are visible on consent screen
	assertClientNameInHTML(t, doc, "My Awesome Application")
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, true)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", true)
	assertClientWebsiteUrlInHTML(t, doc, "https://example.com", true)
}

func TestConsent_ClientDisplay_AllDisabled(t *testing.T) {
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
		ConsentRequired:  true,
		DefaultAcrLevel:  enums.AcrLevel1,
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create user
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Navigate to consent screen
	httpClient := createHttpClient(t)
	resp := navigateToConsentScreen(t, httpClient, client, user, password, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Only client identifier should be visible
	assertClientNameInHTML(t, doc, clientId)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", false)
	assertClientWebsiteUrlInHTML(t, doc, "https://example.com", false)
}
