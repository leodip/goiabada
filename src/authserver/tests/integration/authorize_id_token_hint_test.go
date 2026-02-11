package integrationtests

import (
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

// =============================================================================
// id_token_hint Persistence Tests
// =============================================================================

// TestIdTokenHint_PromptLogin_MismatchedUser_BlocksAtIssuance verifies that:
// 1. id_token_hint is stored in AuthContext from the authorize endpoint
// 2. The hint persists through the entire authentication state machine
// 3. The issuance endpoint detects user mismatch and returns error=login_required
// 4. State parameter is preserved in the error response
func TestIdTokenHint_PromptLogin_MismatchedUser_BlocksAtIssuance(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	// =========================================================================
	// Step 1: Create User A and User B
	// =========================================================================
	passwordA := gofakeit.Password(true, true, true, true, false, 10)
	passwordHashedA, err := hashutil.HashPassword(passwordA)
	assert.NoError(t, err)

	userA := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashedA,
	}
	err = database.CreateUser(nil, userA)
	assert.NoError(t, err)

	passwordB := gofakeit.Password(true, true, true, true, false, 10)
	passwordHashedB, err := hashutil.HashPassword(passwordB)
	assert.NoError(t, err)

	userB := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashedB,
	}
	err = database.CreateUser(nil, userB)
	assert.NoError(t, err)

	// =========================================================================
	// Step 2: Create client with confidential credentials
	// =========================================================================
	clientSecret := gofakeit.LetterN(32)
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// =========================================================================
	// Step 3: Get an ID token for User A (complete full auth flow)
	// =========================================================================
	httpClientA := createHttpClient(t)
	codeVerifierA := "code-verifier-a"
	requestCodeChallengeA := oauth.GeneratePKCECodeChallenge(codeVerifierA)
	requestStateA := gofakeit.LetterN(8)
	requestNonceA := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrlA := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallengeA +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestStateA +
		"&nonce=" + requestNonceA

	// Start auth flow for User A
	respA, err := httpClientA.Get(destUrlA)
	assert.NoError(t, err)
	defer func() { _ = respA.Body.Close() }()

	redirectLocation := assertRedirect(t, respA, "/auth/level1")
	respA = loadPage(t, httpClientA, redirectLocation)
	defer func() { _ = respA.Body.Close() }()

	redirectLocation = assertRedirect(t, respA, "/auth/pwd")
	respA = loadPage(t, httpClientA, redirectLocation)
	defer func() { _ = respA.Body.Close() }()

	csrf := getCsrfValue(t, respA)
	respA = authenticateWithPassword(t, httpClientA, redirectLocation, userA.Email, passwordA, csrf)
	defer func() { _ = respA.Body.Close() }()

	redirectLocation = assertRedirect(t, respA, "/auth/level1completed")
	respA = loadPage(t, httpClientA, redirectLocation)
	defer func() { _ = respA.Body.Close() }()

	redirectLocation = assertRedirect(t, respA, "/auth/completed")
	respA = loadPage(t, httpClientA, redirectLocation)
	defer func() { _ = respA.Body.Close() }()

	redirectLocation = assertRedirect(t, respA, "/auth/issue")
	respA = loadPage(t, httpClientA, redirectLocation)
	defer func() { _ = respA.Body.Close() }()

	codeA, stateA := getCodeAndStateFromUrl(t, respA)
	assert.Equal(t, requestStateA, stateA)

	// Exchange code for tokens to get User A's ID token
	tokenUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	formDataA := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeA},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifierA},
	}

	tokenDataA := postToTokenEndpoint(t, httpClientA, tokenUrl, formDataA)
	assert.NotNil(t, tokenDataA["id_token"], "id_token should be present in token response")
	idTokenUserA := tokenDataA["id_token"].(string)
	assert.NotEmpty(t, idTokenUserA)

	// Verify User A's ID token contains correct subject
	idClaimsA := decodeJWTPayload(t, idTokenUserA)
	assert.Equal(t, userA.Subject.String(), idClaimsA["sub"], "ID token should have User A's subject")

	// =========================================================================
	// Step 4: Start NEW auth request with id_token_hint and prompt=login
	// Use a fresh HTTP client (no cookies, simulating fresh browser)
	// =========================================================================
	httpClientB := createHttpClient(t) // Fresh client, no session
	codeVerifierB := "code-verifier-b"
	requestCodeChallengeB := oauth.GeneratePKCECodeChallenge(codeVerifierB)
	requestStateB := gofakeit.LetterN(8)
	requestNonceB := gofakeit.LetterN(8)

	destUrlB := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallengeB +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestStateB +
		"&nonce=" + requestNonceB +
		"&id_token_hint=" + url.QueryEscape(idTokenUserA) +
		"&prompt=login"

	// =========================================================================
	// Step 5: User B authenticates (different user than the hint)
	// =========================================================================
	respB, err := httpClientB.Get(destUrlB)
	assert.NoError(t, err)
	defer func() { _ = respB.Body.Close() }()

	// Should redirect to login even with prompt=login (since no session exists)
	redirectLocation = assertRedirect(t, respB, "/auth/level1")
	respB = loadPage(t, httpClientB, redirectLocation)
	defer func() { _ = respB.Body.Close() }()

	redirectLocation = assertRedirect(t, respB, "/auth/pwd")
	respB = loadPage(t, httpClientB, redirectLocation)
	defer func() { _ = respB.Body.Close() }()

	csrf = getCsrfValue(t, respB)
	respB = authenticateWithPassword(t, httpClientB, redirectLocation, userB.Email, passwordB, csrf)
	defer func() { _ = respB.Body.Close() }()

	redirectLocation = assertRedirect(t, respB, "/auth/level1completed")
	respB = loadPage(t, httpClientB, redirectLocation)
	defer func() { _ = respB.Body.Close() }()

	redirectLocation = assertRedirect(t, respB, "/auth/completed")
	respB = loadPage(t, httpClientB, redirectLocation)
	defer func() { _ = respB.Body.Close() }()

	// =========================================================================
	// Step 6: At /auth/issue, expect error=login_required due to mismatch
	// =========================================================================
	redirectLocation = assertRedirect(t, respB, "/auth/issue")
	respB = loadPage(t, httpClientB, redirectLocation)
	defer func() { _ = respB.Body.Close() }()

	// Should redirect back to client with error
	assert.Equal(t, 302, respB.StatusCode, "Expected redirect to client callback")

	errorCode, errorDescription, state := getErrorFromUrl(t, respB)

	// Verify error response
	assert.Equal(t, "login_required", errorCode,
		"Expected error=login_required when authenticated user differs from id_token_hint subject")
	assert.Contains(t, errorDescription, "authenticated user",
		"Error description should mention user mismatch")
	assert.Equal(t, requestStateB, state,
		"State parameter should be preserved in error response")

	// Verify redirect goes to the correct callback URI
	location := respB.Header.Get("Location")
	assert.Contains(t, location, redirectUri.URI,
		"Should redirect to client's registered redirect_uri")
}

// TestIdTokenHint_PromptLogin_MatchingUser_Success verifies that when the
// id_token_hint matches the authenticated user, the flow completes successfully.
func TestIdTokenHint_PromptLogin_MatchingUser_Success(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	// =========================================================================
	// Step 1: Create User A
	// =========================================================================
	password := gofakeit.Password(true, true, true, true, false, 10)
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

	// =========================================================================
	// Step 2: Create client
	// =========================================================================
	clientSecret := gofakeit.LetterN(32)
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// =========================================================================
	// Step 3: Get an ID token for User A
	// =========================================================================
	httpClient1 := createHttpClient(t)
	codeVerifier1 := "code-verifier-1"
	requestCodeChallenge1 := oauth.GeneratePKCECodeChallenge(codeVerifier1)
	requestState1 := gofakeit.LetterN(8)
	requestNonce1 := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl1 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge1 +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState1 +
		"&nonce=" + requestNonce1

	resp, err := httpClient1.Get(destUrl1)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient1, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient1, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	resp = authenticateWithPassword(t, httpClient1, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient1, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient1, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient1, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	code1, state1 := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState1, state1)

	// Exchange code for tokens
	tokenUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	formData1 := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code1},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier1},
	}

	tokenData1 := postToTokenEndpoint(t, httpClient1, tokenUrl, formData1)
	assert.NotNil(t, tokenData1["id_token"])
	idToken := tokenData1["id_token"].(string)
	assert.NotEmpty(t, idToken)

	// Verify ID token
	idClaims := decodeJWTPayload(t, idToken)
	assert.Equal(t, user.Subject.String(), idClaims["sub"])

	// =========================================================================
	// Step 4: Start NEW auth with same user using id_token_hint + prompt=login
	// =========================================================================
	httpClient2 := createHttpClient(t) // Fresh client
	codeVerifier2 := "code-verifier-2"
	requestCodeChallenge2 := oauth.GeneratePKCECodeChallenge(codeVerifier2)
	requestState2 := gofakeit.LetterN(8)
	requestNonce2 := gofakeit.LetterN(8)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge2 +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState2 +
		"&nonce=" + requestNonce2 +
		"&id_token_hint=" + url.QueryEscape(idToken) +
		"&prompt=login"

	// =========================================================================
	// Step 5: Same user authenticates again
	// =========================================================================
	resp2, err := httpClient2.Get(destUrl2)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/level1")
	resp2 = loadPage(t, httpClient2, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/pwd")
	resp2 = loadPage(t, httpClient2, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	csrf = getCsrfValue(t, resp2)
	resp2 = authenticateWithPassword(t, httpClient2, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/level1completed")
	resp2 = loadPage(t, httpClient2, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation = assertRedirect(t, resp2, "/auth/completed")
	resp2 = loadPage(t, httpClient2, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	// =========================================================================
	// Step 6: Should succeed and issue code (user matches hint)
	// =========================================================================
	redirectLocation = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient2, redirectLocation)
	defer func() { _ = resp2.Body.Close() }()

	// Should get a code, not an error
	code2, state2 := getCodeAndStateFromUrl(t, resp2)
	assert.NotEmpty(t, code2, "Should receive authorization code when user matches id_token_hint")
	assert.Equal(t, requestState2, state2)

	// Exchange code for new tokens - should succeed
	formData2 := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code2},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifier2},
	}

	tokenData2 := postToTokenEndpoint(t, httpClient2, tokenUrl, formData2)
	assert.NotNil(t, tokenData2["access_token"], "Should receive access_token")
	assert.NotNil(t, tokenData2["id_token"], "Should receive id_token")

	// Verify new ID token still has same subject
	newIdToken := tokenData2["id_token"].(string)
	newIdClaims := decodeJWTPayload(t, newIdToken)
	assert.Equal(t, user.Subject.String(), newIdClaims["sub"])
}

// TestIdTokenHint_NoPrompt_MismatchedUser_BlocksAtIssuance verifies that
// id_token_hint works even without prompt=login parameter.
func TestIdTokenHint_NoPrompt_MismatchedUser_BlocksAtIssuance(t *testing.T) {
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	// Create two users
	passwordA := gofakeit.Password(true, true, true, true, false, 10)
	passwordHashedA, err := hashutil.HashPassword(passwordA)
	assert.NoError(t, err)

	userA := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashedA,
	}
	err = database.CreateUser(nil, userA)
	assert.NoError(t, err)

	passwordB := gofakeit.Password(true, true, true, true, false, 10)
	passwordHashedB, err := hashutil.HashPassword(passwordB)
	assert.NoError(t, err)

	userB := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashedB,
	}
	err = database.CreateUser(nil, userB)
	assert.NoError(t, err)

	// Create client
	clientSecret := gofakeit.LetterN(32)
	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 false,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      "https://example.com/callback",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

	// Get ID token for User A (complete flow and token exchange)
	httpClientA := createHttpClient(t)
	codeVerifierA := "code-verifier-a"
	requestCodeChallengeA := oauth.GeneratePKCECodeChallenge(codeVerifierA)
	requestStateA := gofakeit.LetterN(8)
	requestNonceA := gofakeit.LetterN(8)
	requestScope := "openid profile"

	destUrlA := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallengeA +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestStateA +
		"&nonce=" + requestNonceA

	respA, err := httpClientA.Get(destUrlA)
	assert.NoError(t, err)
	defer func() { _ = respA.Body.Close() }()

	redirectLocation := assertRedirect(t, respA, "/auth/level1")
	respA = loadPage(t, httpClientA, redirectLocation)
	defer func() { _ = respA.Body.Close() }()

	redirectLocation = assertRedirect(t, respA, "/auth/pwd")
	respA = loadPage(t, httpClientA, redirectLocation)
	defer func() { _ = respA.Body.Close() }()

	csrf := getCsrfValue(t, respA)
	respA = authenticateWithPassword(t, httpClientA, redirectLocation, userA.Email, passwordA, csrf)
	defer func() { _ = respA.Body.Close() }()

	redirectLocation = assertRedirect(t, respA, "/auth/level1completed")
	respA = loadPage(t, httpClientA, redirectLocation)
	defer func() { _ = respA.Body.Close() }()

	redirectLocation = assertRedirect(t, respA, "/auth/completed")
	respA = loadPage(t, httpClientA, redirectLocation)
	defer func() { _ = respA.Body.Close() }()

	redirectLocation = assertRedirect(t, respA, "/auth/issue")
	respA = loadPage(t, httpClientA, redirectLocation)
	defer func() { _ = respA.Body.Close() }()

	codeA, _ := getCodeAndStateFromUrl(t, respA)

	// Exchange for ID token
	tokenUrl := config.GetAuthServer().BaseURL + "/auth/token/"
	formDataA := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {codeA},
		"redirect_uri":  {redirectUri.URI},
		"code_verifier": {codeVerifierA},
	}

	tokenDataA := postToTokenEndpoint(t, httpClientA, tokenUrl, formDataA)
	idTokenUserA := tokenDataA["id_token"].(string)

	// Start new auth with User B using User A's id_token_hint (NO prompt parameter)
	httpClientB := createHttpClient(t)
	codeVerifierB := "code-verifier-b"
	requestCodeChallengeB := oauth.GeneratePKCECodeChallenge(codeVerifierB)
	requestStateB := gofakeit.LetterN(8)
	requestNonceB := gofakeit.LetterN(8)

	// Note: NO prompt=login parameter here
	destUrlB := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallengeB +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestStateB +
		"&nonce=" + requestNonceB +
		"&id_token_hint=" + url.QueryEscape(idTokenUserA)

	// User B authenticates
	respB, err := httpClientB.Get(destUrlB)
	assert.NoError(t, err)
	defer func() { _ = respB.Body.Close() }()

	redirectLocation = assertRedirect(t, respB, "/auth/level1")
	respB = loadPage(t, httpClientB, redirectLocation)
	defer func() { _ = respB.Body.Close() }()

	redirectLocation = assertRedirect(t, respB, "/auth/pwd")
	respB = loadPage(t, httpClientB, redirectLocation)
	defer func() { _ = respB.Body.Close() }()

	csrf = getCsrfValue(t, respB)
	respB = authenticateWithPassword(t, httpClientB, redirectLocation, userB.Email, passwordB, csrf)
	defer func() { _ = respB.Body.Close() }()

	redirectLocation = assertRedirect(t, respB, "/auth/level1completed")
	respB = loadPage(t, httpClientB, redirectLocation)
	defer func() { _ = respB.Body.Close() }()

	redirectLocation = assertRedirect(t, respB, "/auth/completed")
	respB = loadPage(t, httpClientB, redirectLocation)
	defer func() { _ = respB.Body.Close() }()

	redirectLocation = assertRedirect(t, respB, "/auth/issue")
	respB = loadPage(t, httpClientB, redirectLocation)
	defer func() { _ = respB.Body.Close() }()

	// Should get error=login_required even without prompt parameter
	errorCode, errorDescription, state := getErrorFromUrl(t, respB)
	assert.Equal(t, "login_required", errorCode,
		"Should return login_required error when user differs from id_token_hint, even without prompt parameter")
	assert.Contains(t, errorDescription, "authenticated user")
	assert.Equal(t, requestStateB, state)
}
