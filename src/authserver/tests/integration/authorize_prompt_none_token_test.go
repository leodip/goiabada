package integrationtests

import (
	"database/sql"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

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

// =============================================================================
// Phase 4: Client Configuration Tests
// =============================================================================

func TestPromptNone_ClientDefaultAcrHigher(t *testing.T) {
	// Create session at level1 using a level1 client
	httpClient, _, _, _, _ := createSessionWithAcrLevel1AndPassword(t)

	// Create a different client with DefaultAcrLevel=level2_optional
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	// prompt=none without acr_values, client default is level2_optional, session is level1
	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "interaction_required", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPromptNone_ClientDefaultAcrSatisfied(t *testing.T) {
	// Client with DefaultAcrLevel=level1, session at level1 - should succeed
	httpClient, client, redirectUri, _ := createSessionWithAcrLevel1(t)

	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, redirectURL.Query().Get("code"), "code should be present")
	assert.Empty(t, redirectURL.Query().Get("error"), "error should not be present")
}

func TestPromptNone_AcrValuesOverridesClientDefault(t *testing.T) {
	// Create session at level1
	httpClient, _, _, _, _ := createSessionWithAcrLevel1AndPassword(t)

	// Create client with DefaultAcrLevel=level2_optional
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}
	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	// Specify acr_values=level1 to override client default of level2_optional
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=none" +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Should succeed because acr_values=level1 overrides client default
	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEmpty(t, redirectURL.Query().Get("code"), "code should be present")
	assert.Empty(t, redirectURL.Query().Get("error"), "error should not be present")
}

// =============================================================================
// Phase 4: Pre-Validation Failure Tests
// =============================================================================

func TestPromptNone_InvalidRedirectUri(t *testing.T) {
	client, _ := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	// Use a redirect_uri that doesn't match the client's registered URIs
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape("https://evil.com/callback") +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Invalid redirect_uri should show error page, NOT redirect to the evil URI
	assert.Equal(t, http.StatusOK, resp.StatusCode, "should return error page, not redirect")

	body := readResponseBody(t, resp)
	assert.Contains(t, body, "error", "should show error page")
}

func TestPromptNone_InvalidClientId(t *testing.T) {
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=nonexistent-client-12345" +
		"&redirect_uri=" + url.QueryEscape("https://example.com/callback") +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Invalid client_id should show error page, NOT redirect
	assert.Equal(t, http.StatusOK, resp.StatusCode, "should return error page, not redirect")

	body := readResponseBody(t, resp)
	assert.Contains(t, body, "error", "should show error page")
}

func TestPromptNone_InvalidResponseType(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=invalid_type" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "unsupported_response_type", errorCode)
	assert.Equal(t, requestState, state)
}

// =============================================================================
// Phase 4: Token Exchange Tests
// =============================================================================

func TestPromptNone_CodeExchange(t *testing.T) {
	// Create a confidential client for token exchange
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	client := &models.Client{
		ClientIdentifier:                        "test-client-" + gofakeit.LetterN(8),
		ClientSecretEncrypted:                   clientSecretEncrypted,
		Enabled:                                 true,
		AuthorizationCodeEnabled:                true,
		ConsentRequired:                         false,
		DefaultAcrLevel:                         enums.AcrLevel1,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}
	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
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

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := createHttpClient(t)
	codeVerifier := "code-verifier"
	codeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)

	// Create session via normal login
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce

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

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	_, _ = getCodeAndStateFromUrl(t, resp)

	// Now use prompt=none with proper PKCE
	codeVerifier2 := "code-verifier-two"
	codeChallenge2 := oauth.GeneratePKCECodeChallenge(codeVerifier2)
	requestState2 := gofakeit.LetterN(8)
	requestNonce2 := "test-nonce-" + gofakeit.LetterN(16)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge2 +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState2 +
		"&nonce=" + requestNonce2 +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	codeVal, _ := getCodeAndStateFromUrl(t, resp2)

	// Exchange code for tokens
	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token"
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier2},
	}

	data := postToTokenEndpoint(t, httpClient, tokenEndpoint, form)

	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, accessToken)

	idToken, ok := data["id_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, idToken)

	// Verify nonce in id_token
	idClaims := decodeJWTPayload(t, idToken)
	assert.Equal(t, requestNonce2, idClaims["nonce"])

	// Verify sub matches user
	assert.Equal(t, user.Subject.String(), idClaims["sub"])
}

func TestPromptNone_SubClaimConsistent(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	client := &models.Client{
		ClientIdentifier:                        "test-client-" + gofakeit.LetterN(8),
		ClientSecretEncrypted:                   clientSecretEncrypted,
		Enabled:                                 true,
		AuthorizationCodeEnabled:                true,
		ConsentRequired:                         false,
		DefaultAcrLevel:                         enums.AcrLevel1,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}
	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
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

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := createHttpClient(t)

	// First login
	codeVerifier1 := "code-verifier-one"
	codeChallenge1 := oauth.GeneratePKCECodeChallenge(codeVerifier1)
	requestState1 := gofakeit.LetterN(8)
	requestNonce1 := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge1 +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState1 +
		"&nonce=" + requestNonce1

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

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal1, _ := getCodeAndStateFromUrl(t, resp)

	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token"
	form1 := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal1},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier1},
	}

	data1 := postToTokenEndpoint(t, httpClient, tokenEndpoint, form1)
	idToken1 := data1["id_token"].(string)
	claims1 := decodeJWTPayload(t, idToken1)
	sub1 := claims1["sub"].(string)

	// prompt=none to get token2
	codeVerifier2 := "code-verifier-two"
	codeChallenge2 := oauth.GeneratePKCECodeChallenge(codeVerifier2)
	requestState2 := gofakeit.LetterN(8)
	requestNonce2 := gofakeit.LetterN(8)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge2 +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState2 +
		"&nonce=" + requestNonce2 +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	codeVal2, _ := getCodeAndStateFromUrl(t, resp2)

	form2 := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal2},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier2},
	}

	data2 := postToTokenEndpoint(t, httpClient, tokenEndpoint, form2)
	idToken2 := data2["id_token"].(string)
	claims2 := decodeJWTPayload(t, idToken2)
	sub2 := claims2["sub"].(string)

	assert.Equal(t, sub1, sub2, "sub claim should be consistent across tokens")
	assert.Equal(t, user.Subject.String(), sub1, "sub should match user's subject")
}

func TestPromptNone_AuthTimePreservedInToken(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	client := &models.Client{
		ClientIdentifier:                        "test-client-" + gofakeit.LetterN(8),
		ClientSecretEncrypted:                   clientSecretEncrypted,
		Enabled:                                 true,
		AuthorizationCodeEnabled:                true,
		ConsentRequired:                         false,
		DefaultAcrLevel:                         enums.AcrLevel1,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}
	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
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

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := createHttpClient(t)

	codeVerifier1 := "code-verifier-one"
	codeChallenge1 := oauth.GeneratePKCECodeChallenge(codeVerifier1)
	requestState1 := gofakeit.LetterN(8)
	requestNonce1 := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge1 +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState1 +
		"&nonce=" + requestNonce1

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

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal1, _ := getCodeAndStateFromUrl(t, resp)

	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token"
	form1 := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal1},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier1},
	}

	data1 := postToTokenEndpoint(t, httpClient, tokenEndpoint, form1)
	idToken1 := data1["id_token"].(string)
	claims1 := decodeJWTPayload(t, idToken1)
	authTime1 := claims1["auth_time"].(float64)

	// Wait to ensure different timestamp
	time.Sleep(200 * time.Millisecond)

	codeVerifier2 := "code-verifier-two"
	codeChallenge2 := oauth.GeneratePKCECodeChallenge(codeVerifier2)
	requestState2 := gofakeit.LetterN(8)
	requestNonce2 := gofakeit.LetterN(8)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge2 +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState2 +
		"&nonce=" + requestNonce2 +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	codeVal2, _ := getCodeAndStateFromUrl(t, resp2)

	form2 := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal2},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier2},
	}

	data2 := postToTokenEndpoint(t, httpClient, tokenEndpoint, form2)
	idToken2 := data2["id_token"].(string)
	claims2 := decodeJWTPayload(t, idToken2)
	authTime2 := claims2["auth_time"].(float64)

	// auth_time should be preserved from original login
	assert.Equal(t, authTime1, authTime2, "auth_time should be preserved from original session")
}

func TestPromptNone_PKCEWrongVerifier(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	client := &models.Client{
		ClientIdentifier:                        "test-client-" + gofakeit.LetterN(8),
		ClientSecretEncrypted:                   clientSecretEncrypted,
		Enabled:                                 true,
		AuthorizationCodeEnabled:                true,
		ConsentRequired:                         false,
		DefaultAcrLevel:                         enums.AcrLevel1,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}
	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
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

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := createHttpClient(t)

	// Create session
	codeVerifierSession := "session-code-verifier"
	codeChallengeSession := oauth.GeneratePKCECodeChallenge(codeVerifierSession)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallengeSession +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce

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

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	_, _ = getCodeAndStateFromUrl(t, resp)

	// prompt=none with PKCE
	correctVerifier := "correct-verifier"
	correctChallenge := oauth.GeneratePKCECodeChallenge(correctVerifier)
	requestState2 := gofakeit.LetterN(8)
	requestNonce2 := gofakeit.LetterN(8)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + correctChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState2 +
		"&nonce=" + requestNonce2 +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	codeVal, _ := getCodeAndStateFromUrl(t, resp2)

	// Try to exchange with WRONG verifier
	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token"
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {"wrong-verifier-value"},
	}

	data := postToTokenEndpoint(t, httpClient, tokenEndpoint, form)

	// Should fail - PKCE verification should reject wrong verifier
	errorVal, hasError := data["error"].(string)
	assert.True(t, hasError, "should have error in response")
	assert.NotEmpty(t, errorVal, "error should not be empty")
}

// =============================================================================
// Token Exchange: Refresh, Nonce, PKCE
// =============================================================================

// TestPromptNone_RefreshWithOfflineAccess verifies that a code obtained via prompt=none
// with offline_access scope can be exchanged for tokens and then refreshed.
func TestPromptNone_RefreshWithOfflineAccess(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	client := &models.Client{
		ClientIdentifier:                        "test-client-" + gofakeit.LetterN(8),
		ClientSecretEncrypted:                   clientSecretEncrypted,
		Enabled:                                 true,
		AuthorizationCodeEnabled:                true,
		ConsentRequired:                         true,
		DefaultAcrLevel:                         enums.AcrLevel1,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}
	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
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

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	// Create consent including offline_access
	consent := &models.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile offline_access",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err = database.CreateUserConsent(nil, consent)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := createHttpClient(t)
	codeVerifier := "code-verifier"
	codeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)

	// Create session via normal login with offline_access
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge +
		"&scope=" + url.QueryEscape("openid profile offline_access") +
		"&state=" + requestState +
		"&nonce=" + requestNonce

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

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// ConsentRequired=true + offline_access → goes to /auth/consent
	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// offline_access always shows consent form, so we must submit it
	csrf = getCsrfValue(t, resp)
	consentEndpoint := config.GetAuthServer().BaseURL + "/auth/consent"
	consentForm := url.Values{
		"gorilla.csrf.Token": {csrf},
		"btnSubmit":          {"submit"},
		"consent0":           {"on"},
		"consent1":           {"on"},
		"consent2":           {"on"},
	}
	consentFormString := consentForm.Encode()
	consentReqBody := strings.NewReader(consentFormString)
	consentReq, err := http.NewRequest("POST", consentEndpoint, consentReqBody)
	if err != nil {
		t.Fatal(err)
	}
	consentReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	consentReq.Header.Set("Referer", consentEndpoint)
	consentReq.Header.Set("Origin", config.GetAuthServer().BaseURL)

	resp, err = httpClient.Do(consentReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	_, _ = getCodeAndStateFromUrl(t, resp)

	// Now use prompt=none with offline_access
	codeVerifier2 := "code-verifier-two"
	codeChallenge2 := oauth.GeneratePKCECodeChallenge(codeVerifier2)
	requestState2 := gofakeit.LetterN(8)
	requestNonce2 := gofakeit.LetterN(8)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge2 +
		"&scope=" + url.QueryEscape("openid profile offline_access") +
		"&state=" + requestState2 +
		"&nonce=" + requestNonce2 +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	codeVal, _ := getCodeAndStateFromUrl(t, resp2)

	// Exchange code for tokens
	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token"
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier2},
	}

	data := postToTokenEndpoint(t, httpClient, tokenEndpoint, form)

	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, accessToken)

	refreshToken, ok := data["refresh_token"].(string)
	assert.True(t, ok, "should have refresh_token with offline_access")
	assert.NotEmpty(t, refreshToken)

	// Now refresh the token
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
	}

	refreshData := postToTokenEndpoint(t, httpClient, tokenEndpoint, refreshForm)

	newAccessToken, ok := refreshData["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, newAccessToken)

	newRefreshToken, ok := refreshData["refresh_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, newRefreshToken)

	assert.Equal(t, "Bearer", refreshData["token_type"])
}

// TestPromptNone_NoncePreserved verifies that the nonce parameter in a prompt=none
// request is preserved in the issued id_token.
func TestPromptNone_NoncePreserved(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	client := &models.Client{
		ClientIdentifier:                        "test-client-" + gofakeit.LetterN(8),
		ClientSecretEncrypted:                   clientSecretEncrypted,
		Enabled:                                 true,
		AuthorizationCodeEnabled:                true,
		ConsentRequired:                         false,
		DefaultAcrLevel:                         enums.AcrLevel1,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}
	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
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

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := createHttpClient(t)
	codeVerifier := "code-verifier"
	codeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	requestState := gofakeit.LetterN(8)

	// Create session via normal login
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + gofakeit.LetterN(8)

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

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	_, _ = getCodeAndStateFromUrl(t, resp)

	// Now use prompt=none with a specific nonce
	codeVerifier2 := "code-verifier-two"
	codeChallenge2 := oauth.GeneratePKCECodeChallenge(codeVerifier2)
	requestState2 := gofakeit.LetterN(8)
	testNonce := "test-nonce-" + gofakeit.LetterN(16)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge2 +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState2 +
		"&nonce=" + testNonce +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	codeVal, _ := getCodeAndStateFromUrl(t, resp2)

	// Exchange code for tokens
	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token"
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier2},
	}

	data := postToTokenEndpoint(t, httpClient, tokenEndpoint, form)

	idToken, ok := data["id_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, idToken)

	// Verify nonce is preserved in id_token
	idClaims := decodeJWTPayload(t, idToken)
	assert.Equal(t, testNonce, idClaims["nonce"], "nonce should be preserved in id_token")
}

// TestPromptNone_PKCESupported verifies that PKCE works correctly with prompt=none
// (success case - correct verifier).
func TestPromptNone_PKCESupported(t *testing.T) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	client := &models.Client{
		ClientIdentifier:                        "test-client-" + gofakeit.LetterN(8),
		ClientSecretEncrypted:                   clientSecretEncrypted,
		Enabled:                                 true,
		AuthorizationCodeEnabled:                true,
		ConsentRequired:                         false,
		DefaultAcrLevel:                         enums.AcrLevel1,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
	}
	err = database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
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

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}
	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := createHttpClient(t)
	codeVerifier := "initial-code-verifier"
	codeChallenge := oauth.GeneratePKCECodeChallenge(codeVerifier)
	requestState := gofakeit.LetterN(8)

	// Create session via normal login
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + codeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + gofakeit.LetterN(8)

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

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	_, _ = getCodeAndStateFromUrl(t, resp)

	// Now use prompt=none with a NEW PKCE code_challenge/verifier pair
	pkceVerifier := "pkce-verifier-for-prompt-none-test"
	pkceChallenge := oauth.GeneratePKCECodeChallenge(pkceVerifier)
	requestState2 := gofakeit.LetterN(8)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + pkceChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState2 +
		"&nonce=" + gofakeit.LetterN(8) +
		"&prompt=none"

	resp2, err := httpClient.Get(destUrl2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	codeVal, _ := getCodeAndStateFromUrl(t, resp2)

	// Exchange code for tokens using the correct PKCE verifier
	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token"
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeVal},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {pkceVerifier},
	}

	data := postToTokenEndpoint(t, httpClient, tokenEndpoint, form)

	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, accessToken, "PKCE should succeed with correct verifier")

	idToken, ok := data["id_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, idToken)
}
