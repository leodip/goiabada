package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIUserConsentsGet tests the GET /api/v1/admin/users/{id}/consents endpoint
func TestAPIUserConsentsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@consents.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test clients
	client1 := createTestClient(t, "test-client-1")
	client2 := createTestClient(t, "test-client-2")
	defer func() {
		_ = database.DeleteClient(context.Background(), nil, client1.ID)
		_ = database.DeleteClient(context.Background(), nil, client2.ID)
	}()

	// Setup: Create test consents
	consent1 := createTestUserConsent(t, testUser.ID, client1.ID)
	consent2 := createTestUserConsent(t, testUser.ID, client2.ID)
	defer func() {
		_, _ = database.DeleteUserConsent(context.Background(), nil, consent1.ID)
		_, _ = database.DeleteUserConsent(context.Background(), nil, consent2.ID)
	}()

	// Test: Get user consents
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/consents"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetUserConsentsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: Should return both consents
	assert.Len(t, getResponse.Consents, 2)

	// Create a map for easier assertion
	consentMap := make(map[int64]api.UserConsentResponse)
	for _, consent := range getResponse.Consents {
		consentMap[consent.ID] = consent
	}

	// Verify both consents are present
	c1, exists := consentMap[consent1.ID]
	assert.True(t, exists)
	assert.Equal(t, consent1.Scope, c1.Scope)
	assert.Equal(t, client1.ID, c1.ClientID)
	assert.Equal(t, client1.ClientIdentifier, c1.ClientIdentifier)
	assert.Equal(t, client1.Description, c1.ClientDescription)
	assert.Equal(t, testUser.ID, c1.UserID)

	c2, exists := consentMap[consent2.ID]
	assert.True(t, exists)
	assert.Equal(t, consent2.Scope, c2.Scope)
	assert.Equal(t, client2.ID, c2.ClientID)
	assert.Equal(t, client2.ClientIdentifier, c2.ClientIdentifier)
	assert.Equal(t, client2.Description, c2.ClientDescription)
	assert.Equal(t, testUser.ID, c2.UserID)
}

func TestAPIUserConsentsGet_EmptyConsents(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without consents
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@empty-consents.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Get user consents for user with no consents
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/consents"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetUserConsentsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: Should return empty consents array
	assert.Empty(t, getResponse.Consents)
}

func TestAPIUserConsentsGet_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get consents for non-existent user
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/99999/consents"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserConsentsGet_InvalidID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		userID         string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		// An empty segment matches no route, so the group answers 404 (#462 decision 4).
		{"empty ID", "", http.StatusNotFound},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + tc.userID + "/consents"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserConsentsGet_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@unauth-consents.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/consents"
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserConsentDelete tests the DELETE /api/v1/admin/user-consents/{id} endpoint
func TestAPIUserConsentDelete_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@consent-delete.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test client
	client := createTestClient(t, "test-client-delete")
	defer func() {
		_ = database.DeleteClient(context.Background(), nil, client.ID)
	}()

	// Setup: Create test consent
	consent := createTestUserConsent(t, testUser.ID, client.ID)

	// Test: Delete consent
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-consents/" + strconv.FormatInt(consent.ID, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var deleteResponse api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&deleteResponse)
	require.NoError(t, err)

	// Assert: Success response
	assert.True(t, deleteResponse.Success)

	// Verify consent was actually deleted from database
	deletedConsent, err := database.GetUserConsentByID(context.Background(), nil, consent.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedConsent)
}

// The admin console's user page withdraws a consent through this endpoint, and the withdrawal
// revokes the refresh tokens the user holds with that client, of a client whose Consent required
// is off too, while the user's grant with another client keeps refreshing (#622).
func TestAPIUserConsentDelete_RevokesTheClientsRefreshTokens(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, adminClient := createAdminClientWithToken(t)

	password := fake.Password(8)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	defer func() { _ = database.DeleteUser(context.Background(), nil, user.ID) }()
	f := newConsentWithdrawalFixture(t, user, password)

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-consents/" + strconv.FormatInt(f.consent.ID, 10)
	resp := makeAPIRequest(t, "DELETE", url, adminToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Repeated, the DELETE has nothing left to end: 404, and no second audit entry, which the
	// counts below hold (#135 decision 2).
	repeat := makeAPIRequest(t, "DELETE", url, adminToken, nil)
	defer func() { _ = repeat.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, repeat.StatusCode)

	f.assertWithdrawn(t, adminToken, adminClient.ClientIdentifier, audit.EventDeletedUserConsent)
}

func TestAPIUserConsentDelete_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Delete non-existent consent
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-consents/99999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserConsentDelete_InvalidID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		consentID      string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusNotFound},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-consents/" + tc.consentID
			resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserConsentDelete_Unauthorized(t *testing.T) {
	// Setup: Create test user and consent
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@unauth-consent-delete.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test client
	client := createTestClient(t, "test-client-unauth")
	defer func() {
		_ = database.DeleteClient(context.Background(), nil, client.ID)
	}()

	// Setup: Create test consent
	consent := createTestUserConsent(t, testUser.ID, client.ID)
	defer func() {
		_, _ = database.DeleteUserConsent(context.Background(), nil, consent.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-consents/" + strconv.FormatInt(consent.ID, 10)
	req, err := http.NewRequest("DELETE", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify consent was not deleted
	stillExists, err := database.GetUserConsentByID(context.Background(), nil, consent.ID)
	require.NoError(t, err)
	assert.NotNil(t, stillExists)
}

func TestAPIUserConsentDelete_WithClientDetails(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@consent-client-details.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test client with specific details
	client := &record.Client{
		ClientIdentifier:         "detailed-test-client",
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Detailed Test Client for Consent Deletion",
		Enabled:                  true,
		ConsentRequired:          true,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		TokenExpirationInSeconds: 3600,
	}
	err = database.CreateClient(context.Background(), nil, client)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteClient(context.Background(), nil, client.ID)
	}()

	// Setup: Create test consent with specific scope
	consent := &record.UserConsent{
		ClientID:  client.ID,
		UserID:    testUser.ID,
		Scope:     "openid profile email address phone",
		GrantedAt: sql.NullTime{Time: time.Now().UTC().Add(-24 * time.Hour), Valid: true}, // Granted 24 hours ago
	}
	err = database.CreateUserConsent(context.Background(), nil, consent)
	require.NoError(t, err)

	// First verify the consent exists and has client details when retrieved
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/consents"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var getResponse api.GetUserConsentsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	assert.Len(t, getResponse.Consents, 1)
	retrievedConsent := getResponse.Consents[0]
	assert.Equal(t, consent.ID, retrievedConsent.ID)
	assert.Equal(t, client.ClientIdentifier, retrievedConsent.ClientIdentifier)
	assert.Equal(t, client.Description, retrievedConsent.ClientDescription)
	assert.Equal(t, "openid profile email address phone", retrievedConsent.Scope)

	// Now test deleting the consent
	deleteURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-consents/" + strconv.FormatInt(consent.ID, 10)
	deleteResp := makeAPIRequest(t, "DELETE", deleteURL, accessToken, nil)
	defer func() { _ = deleteResp.Body.Close() }()

	// Assert: Delete should succeed
	assert.Equal(t, http.StatusOK, deleteResp.StatusCode)

	// Verify consent is actually deleted
	deletedConsent, err := database.GetUserConsentByID(context.Background(), nil, consent.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedConsent)

	// Verify user no longer has any consents
	finalResp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = finalResp.Body.Close() }()

	assert.Equal(t, http.StatusOK, finalResp.StatusCode)
	var finalResponse api.GetUserConsentsResponse
	err = json.NewDecoder(finalResp.Body).Decode(&finalResponse)
	require.NoError(t, err)
	assert.Empty(t, finalResponse.Consents)
}

// Helper function to create a test client
func createTestClient(t *testing.T, identifier string) *record.Client {
	client := &record.Client{
		ClientIdentifier:                        identifier,
		ClientSecretEncrypted:                   []byte("encrypted-secret"),
		Description:                             "Test Client for Consents",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                false,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 2592000,
		IncludeOpenIDConnectClaimsInAccessToken: record.ThreeStateSettingDefault.String(),
		DefaultACRLevel:                         record.ACRLevel1,
	}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	return client
}

// Helper function to create a test user consent
func createTestUserConsent(t *testing.T, userID int64, clientID int64) *record.UserConsent {
	consent := &record.UserConsent{
		ClientID:  clientID,
		UserID:    userID,
		Scope:     "openid profile email",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err := database.CreateUserConsent(context.Background(), nil, consent)
	assert.NoError(t, err)
	return consent
}
