package integrationtests

import (
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestAuthOtp_ClientDisplay_ShowDisplayName_Enabled(t *testing.T) {
	// Create client with display name enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		DisplayName:      "My Awesome Application",
		ShowDisplayName:  true,
		ShowLogo:         false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
		ConsentRequired:  false,
		DefaultAcrLevel:  enums.AcrLevel2Mandatory, // Requires OTP
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create user with OTP enabled
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Navigate to OTP screen
	httpClient := createHttpClient(t)
	resp := navigateToOtpScreen(t, httpClient, client, user, password, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert display name is shown
	assertClientNameInHTML(t, doc, "My Awesome Application")
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthOtp_ClientDisplay_AllEnabled_Enabled(t *testing.T) {
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
		ConsentRequired:  false,
		DefaultAcrLevel:  enums.AcrLevel2Mandatory,
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create user with OTP enabled
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Navigate to OTP screen
	httpClient := createHttpClient(t)
	resp := navigateToOtpScreen(t, httpClient, client, user, password, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert all elements are visible
	assertClientNameInHTML(t, doc, "My Awesome Application")
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, true)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", true)
	assertClientWebsiteUrlInHTML(t, doc, "https://example.com", true)
}

func TestAuthOtp_ClientDisplay_AllDisabled_Enabled(t *testing.T) {
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
		UploadLogo:       true,
		ConsentRequired:  false,
		DefaultAcrLevel:  enums.AcrLevel2Mandatory,
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create user with OTP enabled
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Navigate to OTP screen
	httpClient := createHttpClient(t)
	resp := navigateToOtpScreen(t, httpClient, client, user, password, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Only client identifier should be visible
	assertClientNameInHTML(t, doc, clientId)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", false)
	assertClientWebsiteUrlInHTML(t, doc, "https://example.com", false)
}

func TestAuthOtp_ClientDisplay_ShowDisplayName_Enrollment(t *testing.T) {
	// Create client with display name enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + gofakeit.LetterN(8),
		DisplayName:      "My Awesome Application",
		ShowDisplayName:  true,
		ShowLogo:         false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
		ConsentRequired:  false,
		DefaultAcrLevel:  enums.AcrLevel2Mandatory, // Requires OTP
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create user WITHOUT OTP (enrollment scenario)
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false, // No OTP yet
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Navigate to OTP screen (will show enrollment page)
	httpClient := createHttpClient(t)
	resp := navigateToOtpScreen(t, httpClient, client, user, password, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert display name is shown on enrollment page
	assertClientNameInHTML(t, doc, "My Awesome Application")
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteUrlInHTML(t, doc, "", false)
}

func TestAuthOtp_ClientDisplay_AllEnabled_Enrollment(t *testing.T) {
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
		ConsentRequired:  false,
		DefaultAcrLevel:  enums.AcrLevel2Mandatory,
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create user WITHOUT OTP (enrollment scenario)
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Navigate to OTP screen (enrollment)
	httpClient := createHttpClient(t)
	resp := navigateToOtpScreen(t, httpClient, client, user, password, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert all elements are visible on enrollment page
	assertClientNameInHTML(t, doc, "My Awesome Application")
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, true)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", true)
	assertClientWebsiteUrlInHTML(t, doc, "https://example.com", true)
}

func TestAuthOtp_ClientDisplay_AllDisabled_Enrollment(t *testing.T) {
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
		UploadLogo:       true,
		ConsentRequired:  false,
		DefaultAcrLevel:  enums.AcrLevel2Mandatory,
	})

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err := database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Create user WITHOUT OTP (enrollment scenario)
	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	assert.NoError(t, err)

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)

	// Navigate to OTP screen (enrollment)
	httpClient := createHttpClient(t)
	resp := navigateToOtpScreen(t, httpClient, client, user, password, redirectUri.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Only client identifier should be visible on enrollment page
	assertClientNameInHTML(t, doc, clientId)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", false)
	assertClientWebsiteUrlInHTML(t, doc, "https://example.com", false)
}
