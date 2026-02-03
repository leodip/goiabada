package integrationtests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
)

// ============================================================================
// IncludeOpenIDConnectClaimsInIdToken setting tests
// These tests verify the behavior of the setting that controls whether
// OIDC scope-based claims (email, profile, address, phone) are included
// in the ID token or only available via /userinfo endpoint
// ============================================================================

func TestToken_IdToken_OIDCClaims_GlobalDisabled(t *testing.T) {
	// Get settings and disable the global setting
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	originalValue := settings.IncludeOpenIDConnectClaimsInIdToken
	settings.IncludeOpenIDConnectClaimsInIdToken = false
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)

	// Restore original value after test
	defer func() {
		settings.IncludeOpenIDConnectClaimsInIdToken = originalValue
		_ = database.UpdateSettings(nil, settings)
	}()

	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCodeWithUserProfile(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify we got tokens
	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["id_token"])

	// Decode ID token
	idToken := data["id_token"].(string)
	idClaims := decodeJWTPayload(t, idToken)

	// Core OIDC claims should ALWAYS be present
	assert.NotNil(t, idClaims["sub"], "sub claim must always be present")
	assert.NotNil(t, idClaims["iss"], "iss claim must always be present")
	assert.NotNil(t, idClaims["aud"], "aud claim must always be present")
	assert.NotNil(t, idClaims["iat"], "iat claim must always be present")
	assert.NotNil(t, idClaims["exp"], "exp claim must always be present")

	// OIDC scope-based claims should NOT be present when setting is disabled
	assert.Nil(t, idClaims["email"], "email claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["email_verified"], "email_verified claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["name"], "name claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["given_name"], "given_name claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["family_name"], "family_name claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["middle_name"], "middle_name claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["nickname"], "nickname claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["profile"], "profile claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["picture"], "picture claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["website"], "website claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["gender"], "gender claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["birthdate"], "birthdate claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["zoneinfo"], "zoneinfo claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["locale"], "locale claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["phone_number"], "phone_number claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["phone_number_verified"], "phone_number_verified claim should NOT be in ID token when setting is disabled")
	assert.Nil(t, idClaims["address"], "address claim should NOT be in ID token when setting is disabled")

	// But OIDC scope-based claims SHOULD be available via /userinfo
	accessToken := data["access_token"].(string)
	userinfoUrl := config.GetAuthServer().BaseURL + "/userinfo"
	req, err := http.NewRequest("GET", userinfoUrl, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	userinfoResp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = userinfoResp.Body.Close() }()

	assert.Equal(t, http.StatusOK, userinfoResp.StatusCode)

	var userinfo map[string]interface{}
	err = json.NewDecoder(userinfoResp.Body).Decode(&userinfo)
	assert.NoError(t, err)
	assert.NotNil(t, userinfo["email"], "email claim should be available via /userinfo")
	assert.NotNil(t, userinfo["email_verified"], "email_verified claim should be available via /userinfo")
	assert.NotNil(t, userinfo["name"], "name claim should be available via /userinfo")
	assert.NotNil(t, userinfo["given_name"], "given_name claim should be available via /userinfo")
}

func TestToken_IdToken_OIDCClaims_GlobalEnabled(t *testing.T) {
	// Get settings and ensure the global setting is enabled
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	originalValue := settings.IncludeOpenIDConnectClaimsInIdToken
	settings.IncludeOpenIDConnectClaimsInIdToken = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)

	// Restore original value after test
	defer func() {
		settings.IncludeOpenIDConnectClaimsInIdToken = originalValue
		_ = database.UpdateSettings(nil, settings)
	}()

	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCodeWithUserProfile(t, clientSecret, "openid profile email")

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify we got tokens
	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["id_token"])

	// Decode ID token
	idToken := data["id_token"].(string)
	idClaims := decodeJWTPayload(t, idToken)

	// Core OIDC claims should ALWAYS be present
	assert.NotNil(t, idClaims["sub"], "sub claim must always be present")
	assert.NotNil(t, idClaims["iss"], "iss claim must always be present")
	assert.NotNil(t, idClaims["aud"], "aud claim must always be present")
	assert.NotNil(t, idClaims["iat"], "iat claim must always be present")
	assert.NotNil(t, idClaims["exp"], "exp claim must always be present")

	// OIDC scope-based claims SHOULD be present when setting is enabled
	assert.NotNil(t, idClaims["email"], "email claim should be in ID token when setting is enabled")
	assert.NotNil(t, idClaims["email_verified"], "email_verified claim should be in ID token when setting is enabled")
	assert.NotNil(t, idClaims["name"], "name claim should be in ID token when setting is enabled")
	assert.NotNil(t, idClaims["given_name"], "given_name claim should be in ID token when setting is enabled")
	assert.NotNil(t, idClaims["family_name"], "family_name claim should be in ID token when setting is enabled")
	assert.NotNil(t, idClaims["middle_name"], "middle_name claim should be in ID token when setting is enabled")
}

func TestToken_IdToken_OIDCClaims_ClientOverride_On(t *testing.T) {
	// Get settings and disable the global setting
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	originalValue := settings.IncludeOpenIDConnectClaimsInIdToken
	settings.IncludeOpenIDConnectClaimsInIdToken = false // Global disabled
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)

	// Restore original value after test
	defer func() {
		settings.IncludeOpenIDConnectClaimsInIdToken = originalValue
		_ = database.UpdateSettings(nil, settings)
	}()

	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCodeWithUserProfile(t, clientSecret, "openid profile email")

	// Set client-level override to "on"
	originalClientSetting := code.Client.IncludeOpenIDConnectClaimsInIdToken
	code.Client.IncludeOpenIDConnectClaimsInIdToken = "on"
	err = database.UpdateClient(nil, &code.Client)
	assert.NoError(t, err)
	defer func() {
		code.Client.IncludeOpenIDConnectClaimsInIdToken = originalClientSetting
		_ = database.UpdateClient(nil, &code.Client)
	}()

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify we got tokens
	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["id_token"])

	// Decode ID token
	idToken := data["id_token"].(string)
	idClaims := decodeJWTPayload(t, idToken)

	// OIDC scope-based claims SHOULD be present because client override is "on"
	assert.NotNil(t, idClaims["email"], "email claim should be in ID token when client override is 'on'")
	assert.NotNil(t, idClaims["email_verified"], "email_verified claim should be in ID token when client override is 'on'")
	assert.NotNil(t, idClaims["name"], "name claim should be in ID token when client override is 'on'")
	assert.NotNil(t, idClaims["given_name"], "given_name claim should be in ID token when client override is 'on'")
}

func TestToken_IdToken_OIDCClaims_ClientOverride_Off(t *testing.T) {
	// Get settings and enable the global setting
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	originalValue := settings.IncludeOpenIDConnectClaimsInIdToken
	settings.IncludeOpenIDConnectClaimsInIdToken = true // Global enabled
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)

	// Restore original value after test
	defer func() {
		settings.IncludeOpenIDConnectClaimsInIdToken = originalValue
		_ = database.UpdateSettings(nil, settings)
	}()

	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCodeWithUserProfile(t, clientSecret, "openid profile email")

	// Set client-level override to "off"
	originalClientSetting := code.Client.IncludeOpenIDConnectClaimsInIdToken
	code.Client.IncludeOpenIDConnectClaimsInIdToken = "off"
	err = database.UpdateClient(nil, &code.Client)
	assert.NoError(t, err)
	defer func() {
		code.Client.IncludeOpenIDConnectClaimsInIdToken = originalClientSetting
		_ = database.UpdateClient(nil, &code.Client)
	}()

	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	// Verify we got tokens
	assert.NotNil(t, data["access_token"])
	assert.NotNil(t, data["id_token"])

	// Decode ID token
	idToken := data["id_token"].(string)
	idClaims := decodeJWTPayload(t, idToken)

	// OIDC scope-based claims should NOT be present because client override is "off"
	assert.Nil(t, idClaims["email"], "email claim should NOT be in ID token when client override is 'off'")
	assert.Nil(t, idClaims["email_verified"], "email_verified claim should NOT be in ID token when client override is 'off'")
	assert.Nil(t, idClaims["name"], "name claim should NOT be in ID token when client override is 'off'")
	assert.Nil(t, idClaims["given_name"], "given_name claim should NOT be in ID token when client override is 'off'")
}

// createAuthCodeWithUserProfile creates a user with full profile data and completes auth code flow
func createAuthCodeWithUserProfile(t *testing.T, clientSecret string, scope string) (*http.Client, *models.Code) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}

	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	// Create user with full profile data
	user := &models.User{
		Subject:             uuid.New(),
		Enabled:             true,
		Email:               gofakeit.Email(),
		EmailVerified:       true,
		PasswordHash:        passwordHashed,
		GivenName:           gofakeit.FirstName(),
		FamilyName:          gofakeit.LastName(),
		MiddleName:          gofakeit.MiddleName(),
		Nickname:            gofakeit.Username(),
		Website:             gofakeit.URL(),
		Gender:              gofakeit.Gender(),
		BirthDate:           sql.NullTime{Time: gofakeit.Date(), Valid: true},
		ZoneInfo:            gofakeit.TimeZoneFull(),
		Locale:              "en-US",
		PhoneNumber:         gofakeit.Phone(),
		PhoneNumberVerified: true,
		AddressLine1:        gofakeit.Street(),
		AddressLine2:        gofakeit.StreetNumber(),
		AddressLocality:     gofakeit.City(),
		AddressRegion:       gofakeit.State(),
		AddressPostalCode:   gofakeit.Zip(),
		AddressCountry:      "US",
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	codeVerifier := "code-verifier"
	requestCodeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)
	code.Code = codeVal
	return httpClient, code
}
