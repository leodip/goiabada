package integrationtests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIUserConsentsGet tests the GET /api/v1/admin/users/{id}/consents endpoint
func TestAPIUserConsentsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@consents.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test clients
	client1 := createTestClient(t, "test-client-1")
	client2 := createTestClient(t, "test-client-2")
	defer func() {
		_ = database.DeleteClient(nil, client1.Id)
		_ = database.DeleteClient(nil, client2.Id)
	}()

	// Setup: Create test consents
	consent1 := createTestUserConsent(t, testUser.Id, client1.Id)
	consent2 := createTestUserConsent(t, testUser.Id, client2.Id)
	defer func() {
		_ = database.DeleteUserConsent(nil, consent1.Id)
		_ = database.DeleteUserConsent(nil, consent2.Id)
	}()

	// Test: Get user consents
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/consents"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetUserConsentsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return both consents
	assert.Len(t, getResponse.Consents, 2)

	// Create a map for easier assertion
	consentMap := make(map[int64]api.UserConsentResponse)
	for _, consent := range getResponse.Consents {
		consentMap[consent.Id] = consent
	}

	// Verify both consents are present
	c1, exists := consentMap[consent1.Id]
	assert.True(t, exists)
	assert.Equal(t, consent1.Scope, c1.Scope)
	assert.Equal(t, client1.Id, c1.ClientId)
	assert.Equal(t, client1.ClientIdentifier, c1.ClientIdentifier)
	assert.Equal(t, client1.Description, c1.ClientDescription)
	assert.Equal(t, testUser.Id, c1.UserId)

	c2, exists := consentMap[consent2.Id]
	assert.True(t, exists)
	assert.Equal(t, consent2.Scope, c2.Scope)
	assert.Equal(t, client2.Id, c2.ClientId)
	assert.Equal(t, client2.ClientIdentifier, c2.ClientIdentifier)
	assert.Equal(t, client2.Description, c2.ClientDescription)
	assert.Equal(t, testUser.Id, c2.UserId)
}

func TestAPIUserConsentsGet_EmptyConsents(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without consents
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@empty-consents.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Get user consents for user with no consents
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/consents"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetUserConsentsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return empty consents array
	assert.Len(t, getResponse.Consents, 0)
}

func TestAPIUserConsentsGet_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get consents for non-existent user
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/consents"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserConsentsGet_InvalidId(t *testing.T) {
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
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.userId + "/consents"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserConsentsGet_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth-consents.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/consents"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserConsentDelete tests the DELETE /api/v1/admin/user-consents/{id} endpoint
func TestAPIUserConsentDelete_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@consent-delete.test",
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
	client := createTestClient(t, "test-client-delete")
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	// Setup: Create test consent
	consent := createTestUserConsent(t, testUser.Id, client.Id)

	// Test: Delete consent
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-consents/" + strconv.FormatInt(consent.Id, 10)
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

	// Verify consent was actually deleted from database
	deletedConsent, err := database.GetUserConsentById(nil, consent.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedConsent)
}

func TestAPIUserConsentDelete_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Delete non-existent consent
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-consents/99999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserConsentDelete_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		consentId      string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusNotFound},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-consents/" + tc.consentId
			resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserConsentDelete_Unauthorized(t *testing.T) {
	// Setup: Create test user and consent
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth-consent-delete.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test client
	client := createTestClient(t, "test-client-unauth")
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	// Setup: Create test consent
	consent := createTestUserConsent(t, testUser.Id, client.Id)
	defer func() {
		_ = database.DeleteUserConsent(nil, consent.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-consents/" + strconv.FormatInt(consent.Id, 10)
	req, err := http.NewRequest("DELETE", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify consent was not deleted
	stillExists, err := database.GetUserConsentById(nil, consent.Id)
	assert.NoError(t, err)
	assert.NotNil(t, stillExists)
}

func TestAPIUserConsentDelete_WithClientDetails(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@consent-client-details.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test client with specific details
	client := &models.Client{
		ClientIdentifier:         "detailed-test-client",
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Detailed Test Client for Consent Deletion",
		Enabled:                  true,
		ConsentRequired:          true,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		TokenExpirationInSeconds: 3600,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	// Setup: Create test consent with specific scope
	consent := &models.UserConsent{
		ClientId:  client.Id,
		UserId:    testUser.Id,
		Scope:     "openid profile email address phone",
		GrantedAt: sql.NullTime{Time: time.Now().UTC().Add(-24 * time.Hour), Valid: true}, // Granted 24 hours ago
	}
	err = database.CreateUserConsent(nil, consent)
	assert.NoError(t, err)

	// First verify the consent exists and has client details when retrieved
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/consents"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var getResponse api.GetUserConsentsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	assert.Len(t, getResponse.Consents, 1)
	retrievedConsent := getResponse.Consents[0]
	assert.Equal(t, consent.Id, retrievedConsent.Id)
	assert.Equal(t, client.ClientIdentifier, retrievedConsent.ClientIdentifier)
	assert.Equal(t, client.Description, retrievedConsent.ClientDescription)
	assert.Equal(t, "openid profile email address phone", retrievedConsent.Scope)

	// Now test deleting the consent
	deleteUrl := config.GetAuthServer().BaseURL + "/api/v1/admin/user-consents/" + strconv.FormatInt(consent.Id, 10)
	deleteResp := makeAPIRequest(t, "DELETE", deleteUrl, accessToken, nil)
	defer deleteResp.Body.Close()

	// Assert: Delete should succeed
	assert.Equal(t, http.StatusOK, deleteResp.StatusCode)

	// Verify consent is actually deleted
	deletedConsent, err := database.GetUserConsentById(nil, consent.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedConsent)

	// Verify user no longer has any consents
	finalResp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer finalResp.Body.Close()

	assert.Equal(t, http.StatusOK, finalResp.StatusCode)
	var finalResponse api.GetUserConsentsResponse
	err = json.NewDecoder(finalResp.Body).Decode(&finalResponse)
	assert.NoError(t, err)
	assert.Len(t, finalResponse.Consents, 0)
}

// Helper function to create a test client
func createTestClient(t *testing.T, identifier string) *models.Client {
	client := &models.Client{
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
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		DefaultAcrLevel:                         enums.AcrLevel1,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	return client
}

// Helper function to create a test user consent
func createTestUserConsent(t *testing.T, userId int64, clientId int64) *models.UserConsent {
	consent := &models.UserConsent{
		ClientId:  clientId,
		UserId:    userId,
		Scope:     "openid profile email",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err := database.CreateUserConsent(nil, consent)
	assert.NoError(t, err)
	return consent
}
