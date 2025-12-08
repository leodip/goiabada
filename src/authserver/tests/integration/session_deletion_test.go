package integrationtests

import (
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestSessionDeletedDuringAuthFlow_LoginSucceeds tests that when a user's database session
// is deleted while they are in the middle of an auth flow (e.g., on the password page),
// submitting credentials still succeeds because the AuthContext is preserved in the
// session cookie.
//
// This is a regression test for GitHub issue #46:
// "Login fails silently when database session is deleted during auth flow"
//
// The bug scenario:
// 1. User has a session cookie with SessionKeySessionIdentifier pointing to a DB session
// 2. That DB session gets deleted (expired, deployment, manual cleanup)
// 3. User starts a new auth flow - browser still has the old session cookie
// 4. Middleware clears session identifier but previously also cleared AuthContext (bug)
// 5. User submits credentials on /auth/pwd
// 6. Before fix: Login failed silently (AuthContext was cleared)
// 7. After fix: Login succeeds (AuthContext preserved)
func TestSessionDeletedDuringAuthFlow_LoginSucceeds(t *testing.T) {
	// Step 1: Create a client and user for testing
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	assert.NoError(t, err)

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

	// Step 2: Complete a full login to create a session in the database
	httpClient := createHttpClient(t)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	resp, err := httpClient.Get(destUrl)
	assert.NoError(t, err)
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

	// Verify login succeeded
	_, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	// Step 3: Verify a session was created in the database
	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(userSessions), "Should have exactly one session after login")

	userSession := userSessions[0]

	// Step 4: Delete the session from the database (simulating expiry/deployment)
	err = database.DeleteUserSession(nil, userSession.Id)
	assert.NoError(t, err)

	// Verify session is deleted
	deletedSession, err := database.GetUserSessionBySessionIdentifier(nil, userSession.SessionIdentifier)
	assert.NoError(t, err)
	assert.Nil(t, deletedSession, "Session should be deleted from database")

	// Step 5: Start a NEW auth flow with the same httpClient (which still has the old session cookie)
	// This simulates the user clicking "Login" again after their DB session was deleted
	requestCodeChallenge2 := gofakeit.LetterN(43)
	requestState2 := gofakeit.LetterN(8)
	requestNonce2 := gofakeit.LetterN(8)

	destUrl2 := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge2 +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState2 +
		"&nonce=" + requestNonce2

	resp2, err := httpClient.Get(destUrl2)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()

	// Should redirect to /auth/level1 (starting the auth flow)
	redirectLocation2 := assertRedirect(t, resp2, "/auth/level1")
	resp2 = loadPage(t, httpClient, redirectLocation2)
	defer func() { _ = resp2.Body.Close() }()

	// Should redirect to /auth/pwd (password page)
	redirectLocation2 = assertRedirect(t, resp2, "/auth/pwd")
	resp2 = loadPage(t, httpClient, redirectLocation2)
	defer func() { _ = resp2.Body.Close() }()

	// Step 6: Get CSRF token and submit credentials
	csrf2 := getCsrfValue(t, resp2)

	resp2 = authenticateWithPassword(t, httpClient, redirectLocation2, user.Email, password, csrf2)
	defer func() { _ = resp2.Body.Close() }()

	// Step 7: CRITICAL TEST - After the fix, login should succeed
	// Before the fix, this would redirect back to /auth/pwd (silent failure)
	// After the fix, this should redirect to /auth/level1completed
	redirectLocation2 = assertRedirect(t, resp2, "/auth/level1completed")
	resp2 = loadPage(t, httpClient, redirectLocation2)
	defer func() { _ = resp2.Body.Close() }()

	// Continue the flow to verify it completes successfully
	redirectLocation2 = assertRedirect(t, resp2, "/auth/completed")
	resp2 = loadPage(t, httpClient, redirectLocation2)
	defer func() { _ = resp2.Body.Close() }()

	redirectLocation2 = assertRedirect(t, resp2, "/auth/issue")
	resp2 = loadPage(t, httpClient, redirectLocation2)
	defer func() { _ = resp2.Body.Close() }()

	// Step 8: Verify the second login also succeeded and we got a code
	codeVal2, stateVal2 := getCodeAndStateFromUrl(t, resp2)
	assert.Equal(t, requestState2, stateVal2)
	assert.NotEmpty(t, codeVal2)

	// Verify a new session was created
	userSessions2, err := database.GetUserSessionsByUserId(nil, user.Id)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(userSessions2), "Should have a new session after second login")
}
