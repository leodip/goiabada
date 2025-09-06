package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// Helper function to create a test user session
func createTestUserSession(t *testing.T, userId int64, sessionIdentifier string) *models.UserSession {
	session := &models.UserSession{
		SessionIdentifier:          sessionIdentifier,
		Started:                    time.Now().UTC().Add(-time.Hour), // Started 1 hour ago
		LastAccessed:               time.Now().UTC().Add(-time.Minute * 30), // Last accessed 30 minutes ago
		AuthMethods:                "pwd",
		AcrLevel:                   "urn:goiabada:pwd",
		AuthTime:                   time.Now().UTC().Add(-time.Hour),
		IpAddress:                  "192.168.1.100",
		DeviceName:                 "Test Device",
		DeviceType:                 "computer",
		DeviceOS:                   "linux",
		Level2AuthConfigHasChanged: false,
		UserId:                     userId,
	}
	err := database.CreateUserSession(nil, session)
	assert.NoError(t, err)
	return session
}

// Helper function to create a test client for sessions
func createTestClientForSessions(t *testing.T, identifier string) *models.Client {
	client := &models.Client{
		ClientIdentifier:         identifier,
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Test Client for Sessions",
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	return client
}

// Helper function to create a user session client relationship
func createTestUserSessionClient(t *testing.T, sessionId int64, clientId int64) {
	now := time.Now().UTC()
	sessionClient := &models.UserSessionClient{
		UserSessionId: sessionId,
		ClientId:      clientId,
		Started:       now.Add(-time.Hour),        // Started 1 hour ago
		LastAccessed:  now.Add(-time.Minute * 5), // Last accessed 5 minutes ago
	}
	err := database.CreateUserSessionClient(nil, sessionClient)
	assert.NoError(t, err)
}

// TestAPIUserSessionsGet tests the GET /api/v1/admin/users/{id}/sessions endpoint
func TestAPIUserSessionsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@sessions.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test client
	testClient := createTestClientForSessions(t, "test-client-sessions-"+uuid.New().String()[:8])
	defer func() {
		_ = database.DeleteClient(nil, testClient.Id)
	}()

	// Setup: Create test sessions
	session1 := createTestUserSession(t, testUser.Id, uuid.New().String())
	session2 := createTestUserSession(t, testUser.Id, uuid.New().String())
	defer func() {
		_ = database.DeleteUserSession(nil, session1.Id)
		_ = database.DeleteUserSession(nil, session2.Id)
	}()

	// Setup: Link sessions to client
	createTestUserSessionClient(t, session1.Id, testClient.Id)
	createTestUserSessionClient(t, session2.Id, testClient.Id)

	// Test: Get user sessions
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetUserSessionsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return both sessions
	assert.Len(t, getResponse.Sessions, 2)

	// Verify session data structure
	for _, session := range getResponse.Sessions {
		assert.Greater(t, session.Id, int64(0))
		assert.NotEmpty(t, session.SessionIdentifier)
		assert.NotEmpty(t, session.StartedAt)
		assert.NotEmpty(t, session.DurationSinceStarted)
		assert.NotEmpty(t, session.LastAccessedAt)
		assert.NotEmpty(t, session.DurationSinceLastAccessed)
		assert.Equal(t, "192.168.1.100", session.IpAddress)
		assert.Equal(t, "Test Device", session.DeviceName)
		assert.Equal(t, "computer", session.DeviceType)
		assert.Equal(t, "linux", session.DeviceOS)
		assert.True(t, session.IsValid)
		assert.Equal(t, testUser.Id, session.UserId)
		assert.Contains(t, session.ClientIdentifiers, testClient.ClientIdentifier)
	}
}

func TestAPIUserSessionsGet_EmptySessions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without sessions
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@empty-sessions.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Get user sessions for user with no sessions
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetUserSessionsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return empty sessions array
	assert.Len(t, getResponse.Sessions, 0)
}

func TestAPIUserSessionsGet_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get sessions for non-existent user
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserSessionsGet_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		userId         string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusBadRequest},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.userId + "/sessions"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserSessionsGet_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth-sessions.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/sessions"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIUserSessionsGet_SessionsWithNoClients(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@no-clients.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test session without client relationship
	session := createTestUserSession(t, testUser.Id, uuid.New().String())
	defer func() {
		_ = database.DeleteUserSession(nil, session.Id)
	}()

	// Test: Get user sessions
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetUserSessionsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return session with empty client identifiers
	assert.Len(t, getResponse.Sessions, 1)
	assert.Len(t, getResponse.Sessions[0].ClientIdentifiers, 0)
}

// TestAPIUserSessionDelete tests the DELETE /api/v1/admin/user-sessions/{id} endpoint
func TestAPIUserSessionDelete_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@session-delete.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test session
	session := createTestUserSession(t, testUser.Id, uuid.New().String())

	// Test: Delete user session
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-sessions/" + strconv.FormatInt(session.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var deleteResponse api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&deleteResponse)
	assert.NoError(t, err)

	// Assert: Success response
	assert.True(t, deleteResponse.Success)

	// Verify session was actually deleted from database
	deletedSession, err := database.GetUserSessionById(nil, session.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedSession)
}

func TestAPIUserSessionDelete_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Delete non-existent session
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-sessions/99999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserSessionDelete_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		sessionId      string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusNotFound}, // DELETE on collection endpoint returns 404
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-sessions/" + tc.sessionId
			resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserSessionDelete_Unauthorized(t *testing.T) {
	// Setup: Create test user and session
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@session-delete-unauth.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	session := createTestUserSession(t, testUser.Id, uuid.New().String())
	defer func() {
		_ = database.DeleteUserSession(nil, session.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-sessions/" + strconv.FormatInt(session.Id, 10)
	req, err := http.NewRequest("DELETE", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify session was not deleted
	stillExists, err := database.GetUserSessionById(nil, session.Id)
	assert.NoError(t, err)
	assert.NotNil(t, stillExists)
}

func TestAPIUserSessionDelete_InvalidToken(t *testing.T) {
	// Setup: Create test user and session
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@session-delete-invalid-token.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	session := createTestUserSession(t, testUser.Id, uuid.New().String())
	defer func() {
		_ = database.DeleteUserSession(nil, session.Id)
	}()

	// Test: Request with invalid access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-sessions/" + strconv.FormatInt(session.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, "invalid-token", nil)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify session was not deleted
	stillExists, err := database.GetUserSessionById(nil, session.Id)
	assert.NoError(t, err)
	assert.NotNil(t, stillExists)
}

// Test that sessions are filtered based on validity (following the original handler logic)
func TestAPIUserSessionsGet_OnlyValidSessions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@valid-sessions.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create a valid session (recently accessed)
	validSession := &models.UserSession{
		SessionIdentifier:          uuid.New().String(),
		Started:                    time.Now().UTC().Add(-time.Minute * 30), // Started 30 minutes ago
		LastAccessed:               time.Now().UTC().Add(-time.Minute * 5),  // Last accessed 5 minutes ago
		AuthMethods:                "pwd",
		AcrLevel:                   "urn:goiabada:pwd",
		AuthTime:                   time.Now().UTC().Add(-time.Minute * 30),
		IpAddress:                  "192.168.1.100",
		DeviceName:                 "Valid Session Device",
		DeviceType:                 "computer",
		DeviceOS:                   "linux",
		Level2AuthConfigHasChanged: false,
		UserId:                     testUser.Id,
	}
	err = database.CreateUserSession(nil, validSession)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUserSession(nil, validSession.Id)
	}()

	// Setup: Create an expired session (very old last access)
	expiredSession := &models.UserSession{
		SessionIdentifier:          uuid.New().String(),
		Started:                    time.Now().UTC().Add(-time.Hour * 25), // Started 25 hours ago
		LastAccessed:               time.Now().UTC().Add(-time.Hour * 24), // Last accessed 24 hours ago (expired)
		AuthMethods:                "pwd",
		AcrLevel:                   "urn:goiabada:pwd",
		AuthTime:                   time.Now().UTC().Add(-time.Hour * 25),
		IpAddress:                  "192.168.1.100",
		DeviceName:                 "Expired Session Device",
		DeviceType:                 "computer",
		DeviceOS:                   "linux",
		Level2AuthConfigHasChanged: false,
		UserId:                     testUser.Id,
	}
	err = database.CreateUserSession(nil, expiredSession)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUserSession(nil, expiredSession.Id)
	}()

	// Test: Get user sessions
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/sessions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetUserSessionsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should only return valid session, expired session should be filtered out
	assert.Len(t, getResponse.Sessions, 1)
	assert.Equal(t, validSession.SessionIdentifier, getResponse.Sessions[0].SessionIdentifier)
	assert.Equal(t, "Valid Session Device", getResponse.Sessions[0].DeviceName)
}