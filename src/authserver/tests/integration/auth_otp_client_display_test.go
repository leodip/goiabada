package integration

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/require"
)

func TestAuthOTP_ClientDisplay_ShowDisplayName_Enabled(t *testing.T) {
	// Create client with display name enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + fake.LetterN(8),
		DisplayName:      "My Awesome Application",
		ShowDisplayName:  true,
		ShowLogo:         false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
		ConsentRequired:  false,
		DefaultACRLevel:  record.ACRLevel2Mandatory, // Requires OTP
	})

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}
	err := database.CreateRedirectURI(context.Background(), nil, redirectURI)
	require.NoError(t, err)

	// Create user with OTP enabled
	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)

	userEmail := fake.Email()
	otpSecret := newOTPSecretForTest(t, userEmail)

	user := &record.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              userEmail,
		PasswordHash:       passwordHashed,
		OTPSecretEncrypted: encryptOTPSecretForTest(t, otpSecret),
		OTPEnabled:         true,
	}
	err = database.CreateUser(context.Background(), nil, user)
	require.NoError(t, err)

	// Navigate to OTP screen
	httpClient := createHTTPClient(t)
	resp := navigateToOTPScreen(t, httpClient, client, user, password, redirectURI.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert display name is shown
	assertClientNameInHTML(t, doc, "My Awesome Application")
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteURLInHTML(t, doc, "", false)
}

func TestAuthOTP_ClientDisplay_AllEnabled_Enabled(t *testing.T) {
	// Create client with all display settings enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + fake.LetterN(8),
		DisplayName:      "My Awesome Application",
		Description:      "The best app for testing OAuth flows",
		WebsiteURL:       "https://example.com",
		ShowLogo:         true,
		ShowDisplayName:  true,
		ShowDescription:  true,
		ShowWebsiteURL:   true,
		UploadLogo:       true,
		ConsentRequired:  false,
		DefaultACRLevel:  record.ACRLevel2Mandatory,
	})

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}
	err := database.CreateRedirectURI(context.Background(), nil, redirectURI)
	require.NoError(t, err)

	// Create user with OTP enabled
	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)

	userEmail := fake.Email()
	otpSecret := newOTPSecretForTest(t, userEmail)

	user := &record.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              userEmail,
		PasswordHash:       passwordHashed,
		OTPSecretEncrypted: encryptOTPSecretForTest(t, otpSecret),
		OTPEnabled:         true,
	}
	err = database.CreateUser(context.Background(), nil, user)
	require.NoError(t, err)

	// Navigate to OTP screen
	httpClient := createHTTPClient(t)
	resp := navigateToOTPScreen(t, httpClient, client, user, password, redirectURI.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert all elements are visible
	assertClientNameInHTML(t, doc, "My Awesome Application")
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, true)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", true)
	assertClientWebsiteURLInHTML(t, doc, "https://example.com", true)
}

func TestAuthOTP_ClientDisplay_AllDisabled_Enabled(t *testing.T) {
	// Create client with all display settings disabled
	clientID := "test-app-" + fake.LetterN(8)
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: clientID,
		DisplayName:      "My Awesome Application",
		Description:      "The best app for testing OAuth flows",
		WebsiteURL:       "https://example.com",
		ShowLogo:         false,
		ShowDisplayName:  false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
		UploadLogo:       true,
		ConsentRequired:  false,
		DefaultACRLevel:  record.ACRLevel2Mandatory,
	})

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}
	err := database.CreateRedirectURI(context.Background(), nil, redirectURI)
	require.NoError(t, err)

	// Create user with OTP enabled
	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)

	userEmail := fake.Email()
	otpSecret := newOTPSecretForTest(t, userEmail)

	user := &record.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              userEmail,
		PasswordHash:       passwordHashed,
		OTPSecretEncrypted: encryptOTPSecretForTest(t, otpSecret),
		OTPEnabled:         true,
	}
	err = database.CreateUser(context.Background(), nil, user)
	require.NoError(t, err)

	// Navigate to OTP screen
	httpClient := createHTTPClient(t)
	resp := navigateToOTPScreen(t, httpClient, client, user, password, redirectURI.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Only client identifier should be visible
	assertClientNameInHTML(t, doc, clientID)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", false)
	assertClientWebsiteURLInHTML(t, doc, "https://example.com", false)
}

func TestAuthOTP_ClientDisplay_ShowDisplayName_Enrollment(t *testing.T) {
	// Create client with display name enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + fake.LetterN(8),
		DisplayName:      "My Awesome Application",
		ShowDisplayName:  true,
		ShowLogo:         false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
		ConsentRequired:  false,
		DefaultACRLevel:  record.ACRLevel2Mandatory, // Requires OTP
	})

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}
	err := database.CreateRedirectURI(context.Background(), nil, redirectURI)
	require.NoError(t, err)

	// Create user WITHOUT OTP (enrollment scenario)
	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)

	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false, // No OTP yet
	}
	err = database.CreateUser(context.Background(), nil, user)
	require.NoError(t, err)

	// Navigate to OTP screen (will show enrollment page)
	httpClient := createHTTPClient(t)
	resp := navigateToOTPScreen(t, httpClient, client, user, password, redirectURI.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert display name is shown on enrollment page
	assertClientNameInHTML(t, doc, "My Awesome Application")
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "", false)
	assertClientWebsiteURLInHTML(t, doc, "", false)
}

func TestAuthOTP_ClientDisplay_AllEnabled_Enrollment(t *testing.T) {
	// Create client with all display settings enabled
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: "test-app-" + fake.LetterN(8),
		DisplayName:      "My Awesome Application",
		Description:      "The best app for testing OAuth flows",
		WebsiteURL:       "https://example.com",
		ShowLogo:         true,
		ShowDisplayName:  true,
		ShowDescription:  true,
		ShowWebsiteURL:   true,
		UploadLogo:       true,
		ConsentRequired:  false,
		DefaultACRLevel:  record.ACRLevel2Mandatory,
	})

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}
	err := database.CreateRedirectURI(context.Background(), nil, redirectURI)
	require.NoError(t, err)

	// Create user WITHOUT OTP (enrollment scenario)
	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)

	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}
	err = database.CreateUser(context.Background(), nil, user)
	require.NoError(t, err)

	// Navigate to OTP screen (enrollment)
	httpClient := createHTTPClient(t)
	resp := navigateToOTPScreen(t, httpClient, client, user, password, redirectURI.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Assert all elements are visible on enrollment page
	assertClientNameInHTML(t, doc, "My Awesome Application")
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, true)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", true)
	assertClientWebsiteURLInHTML(t, doc, "https://example.com", true)
}

func TestAuthOTP_ClientDisplay_AllDisabled_Enrollment(t *testing.T) {
	// Create client with all display settings disabled
	clientID := "test-app-" + fake.LetterN(8)
	client := createClientWithDisplaySettings(t, ClientDisplaySettings{
		ClientIdentifier: clientID,
		DisplayName:      "My Awesome Application",
		Description:      "The best app for testing OAuth flows",
		WebsiteURL:       "https://example.com",
		ShowLogo:         false,
		ShowDisplayName:  false,
		ShowDescription:  false,
		ShowWebsiteURL:   false,
		UploadLogo:       true,
		ConsentRequired:  false,
		DefaultACRLevel:  record.ACRLevel2Mandatory,
	})

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}
	err := database.CreateRedirectURI(context.Background(), nil, redirectURI)
	require.NoError(t, err)

	// Create user WITHOUT OTP (enrollment scenario)
	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)

	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}
	err = database.CreateUser(context.Background(), nil, user)
	require.NoError(t, err)

	// Navigate to OTP screen (enrollment)
	httpClient := createHTTPClient(t)
	resp := navigateToOTPScreen(t, httpClient, client, user, password, redirectURI.URI)
	defer func() { _ = resp.Body.Close() }()

	// Parse HTML
	doc := parseHTMLResponse(t, resp)

	// Only client identifier should be visible on enrollment page
	assertClientNameInHTML(t, doc, clientID)
	assertClientLogoInHTML(t, doc, client.ClientIdentifier, false)
	assertClientDescriptionInHTML(t, doc, "The best app for testing OAuth flows", false)
	assertClientWebsiteURLInHTML(t, doc, "https://example.com", false)
}
