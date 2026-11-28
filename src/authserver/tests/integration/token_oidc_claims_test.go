package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/gender"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// IncludeOpenIDConnectClaimsInIDToken setting tests
// These tests verify the behavior of the setting that controls whether
// OIDC scope-based claims (email, profile, address, phone) are included
// in the ID token or only available via /userinfo endpoint
// ============================================================================

func TestToken_IDToken_OIDCClaims_GlobalDisabled(t *testing.T) {
	// Disable the global setting
	changeSettings(t, func(settings *record.Settings) { settings.IncludeOpenIDConnectClaimsInIDToken = false })

	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCodeWithUserProfile(t, clientSecret, "openid profile email")

	destURL := appConfig.AuthServer.BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destURL, formData)

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
	userinfoURL := appConfig.AuthServer.BaseURL + "/userinfo"
	req, err := http.NewRequest("GET", userinfoURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	userinfoResp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = userinfoResp.Body.Close() }()

	assert.Equal(t, http.StatusOK, userinfoResp.StatusCode)

	var userinfo map[string]interface{}
	err = json.NewDecoder(userinfoResp.Body).Decode(&userinfo)
	require.NoError(t, err)
	assert.NotNil(t, userinfo["email"], "email claim should be available via /userinfo")
	assert.NotNil(t, userinfo["email_verified"], "email_verified claim should be available via /userinfo")
	assert.NotNil(t, userinfo["name"], "name claim should be available via /userinfo")
	assert.NotNil(t, userinfo["given_name"], "given_name claim should be available via /userinfo")
}

func TestToken_IDToken_OIDCClaims_GlobalEnabled(t *testing.T) {
	// Ensure the global setting is enabled
	changeSettings(t, func(settings *record.Settings) { settings.IncludeOpenIDConnectClaimsInIDToken = true })

	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCodeWithUserProfile(t, clientSecret, "openid profile email")

	destURL := appConfig.AuthServer.BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destURL, formData)

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

func TestToken_IDToken_OIDCClaims_ClientOverride_On(t *testing.T) {
	// Disable the global setting
	changeSettings(t, func(settings *record.Settings) { settings.IncludeOpenIDConnectClaimsInIDToken = false })

	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCodeWithUserProfile(t, clientSecret, "openid profile email")

	// Set client-level override to "on"
	originalClientSetting := code.Client.IncludeOpenIDConnectClaimsInIDToken
	code.Client.IncludeOpenIDConnectClaimsInIDToken = "on"
	err := database.UpdateClient(context.Background(), nil, &code.Client)
	require.NoError(t, err)
	defer func() {
		code.Client.IncludeOpenIDConnectClaimsInIDToken = originalClientSetting
		_ = database.UpdateClient(context.Background(), nil, &code.Client)
	}()

	destURL := appConfig.AuthServer.BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destURL, formData)

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

func TestToken_IDToken_OIDCClaims_ClientOverride_Off(t *testing.T) {
	// Enable the global setting
	changeSettings(t, func(settings *record.Settings) { settings.IncludeOpenIDConnectClaimsInIDToken = true })

	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCodeWithUserProfile(t, clientSecret, "openid profile email")

	// Set client-level override to "off"
	originalClientSetting := code.Client.IncludeOpenIDConnectClaimsInIDToken
	code.Client.IncludeOpenIDConnectClaimsInIDToken = "off"
	err := database.UpdateClient(context.Background(), nil, &code.Client)
	require.NoError(t, err)
	defer func() {
		code.Client.IncludeOpenIDConnectClaimsInIDToken = originalClientSetting
		_ = database.UpdateClient(context.Background(), nil, &code.Client)
	}()

	destURL := appConfig.AuthServer.BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
		"client_secret": {clientSecret},
	}

	data := postToTokenEndpoint(t, httpClient, destURL, formData)

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
// The name claim an application receives in the ID token and from /userinfo is the full name
// core/personname writes: family name first with no space for a name in kanji, and given, middle,
// family joined by spaces for a Latin name, as before (#662 decision 1). The three parts it is
// written from are sent as they are stored.
func TestToken_NameClaim_IsTheFullName(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) { settings.IncludeOpenIDConnectClaimsInIDToken = true })

	for _, tc := range []struct {
		name                              string
		givenName, middleName, familyName string
		want                              string
	}{
		{"a name in kanji", "太郎", "", "山田", "山田太郎"},
		{"a Latin name", "John", "Quincy", "Smith", "John Quincy Smith"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientSecret := fake.LetterN(32)
			httpClient, code := createAuthCodeWithNamedUser(t, clientSecret, "openid profile",
				tc.givenName, tc.middleName, tc.familyName)

			data := postToTokenEndpoint(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {code.Client.ClientIdentifier},
				"code":          {code.Code},
				"redirect_uri":  {code.RedirectURI},
				"code_verifier": {testCodeVerifier},
				"client_secret": {clientSecret},
			})

			idClaims := decodeJWTPayload(t, data["id_token"].(string))
			assert.Equal(t, tc.want, idClaims["name"], "the ID token's name claim")
			assert.Equal(t, tc.givenName, idClaims["given_name"])
			assert.Equal(t, tc.familyName, idClaims["family_name"])

			req, err := http.NewRequest("GET", appConfig.AuthServer.BaseURL+"/userinfo", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+data["access_token"].(string))
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var userinfo map[string]interface{}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&userinfo))
			assert.Equal(t, tc.want, userinfo["name"], "the UserInfo answer's name claim")
			assert.Equal(t, tc.givenName, userinfo["given_name"])
			assert.Equal(t, tc.familyName, userinfo["family_name"])
		})
	}
}

func createAuthCodeWithUserProfile(t *testing.T, clientSecret string, scope string) (*http.Client, *record.Code) {
	return createAuthCodeWithNamedUser(t, clientSecret, scope, fake.FirstName(), fake.MiddleName(), fake.LastName())
}

// createAuthCodeWithNamedUser is createAuthCodeWithUserProfile for a user whose given, middle and
// family names are the ones named.
func createAuthCodeWithNamedUser(t *testing.T, clientSecret, scope, givenName, middleName, familyName string) (*http.Client, *record.Code) {
	clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)

	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultACRLevel:          record.ACRLevel2Optional,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}

	err = database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectURI := &record.RedirectURI{
		ClientID: client.ID,
		URI:      fake.URL(),
	}

	err = database.CreateRedirectURI(context.Background(), nil, redirectURI)
	if err != nil {
		t.Fatal(err)
	}

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}

	// The gender column is 16 characters and the claim is echoed back verbatim,
	// so the fixture picks one of the two strings gender.Gender.String() returns
	// rather than a generated run (#272).
	genderValue := gender.Female.String()
	if fake.Bool() {
		genderValue = gender.Male.String()
	}

	// Create user with full profile data.
	//
	// ZoneInfo and Locale are the two profile fields ProfileValidator checks
	// against a fixed repository list, so both carry a value from those lists
	// rather than a generated run: a profile the server would refuse at its own
	// API is a weaker thing for the claim assertions to run against. Nothing
	// below asserts on either value, only that the claim carries what was
	// stored (#272).
	user := &record.User{
		Subject:             fake.UUID(),
		Enabled:             true,
		Email:               fake.Email(),
		EmailVerified:       true,
		PasswordHash:        passwordHashed,
		GivenName:           givenName,
		FamilyName:          familyName,
		MiddleName:          middleName,
		Nickname:            fake.Username(),
		Website:             fake.URL(),
		Gender:              genderValue,
		BirthDate:           sql.NullTime{Time: fake.Date(), Valid: true},
		ZoneInfo:            "America/New_York",
		Locale:              "en-US",
		PhoneNumber:         fake.DigitN(10),
		PhoneNumberVerified: true,
		AddressLine1:        "Street " + fake.LetterN(8),
		AddressLine2:        fake.DigitN(3),
		AddressLocality:     "City" + fake.LetterN(6),
		AddressRegion:       "State" + fake.LetterN(6),
		AddressPostalCode:   fake.DigitN(5),
		AddressCountry:      "US",
	}

	err = database.CreateUser(context.Background(), nil, user)
	if err != nil {
		t.Fatal(err)
	}

	codeVerifier := testCodeVerifier
	requestCodeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHTTPClient(t)

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromURL(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)
	code.Code = codeVal
	return httpClient, code
}
