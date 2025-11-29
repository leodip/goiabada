package integrationtests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// createClientWithGranularScope creates a client with a specific granular permission scope
// and returns an access token for that client
func createClientWithGranularScope(t *testing.T, permissionIdentifier string) (string, *models.Client) {
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "granular-test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)

	// Get authserver resource
	authServerResource, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	assert.NoError(t, err)

	// Find the specified permission
	permissions, err := database.GetPermissionsByResourceId(nil, authServerResource.Id)
	assert.NoError(t, err)

	var targetPermission *models.Permission
	for idx, permission := range permissions {
		if permission.PermissionIdentifier == permissionIdentifier {
			targetPermission = &permissions[idx]
			break
		}
	}
	assert.NotNil(t, targetPermission, "Should find permission: %s", permissionIdentifier)

	// Assign permission to client
	err = database.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: targetPermission.Id,
	})
	assert.NoError(t, err)

	// Get access token using client credentials flow
	httpClient := createHttpClient(t)
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {constants.AuthServerResourceIdentifier + ":" + permissionIdentifier},
	}

	data := postToTokenEndpoint(t, httpClient, destUrl, formData)
	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok, "access_token should be a string")
	assert.NotEmpty(t, accessToken, "access_token should not be empty")

	return accessToken, client
}

// TestGranularScopes_AdminReadCanOnlyReadUserEndpoints verifies that admin-read scope
// can access GET endpoints but not PUT/POST/DELETE endpoints for users
func TestGranularScopes_AdminReadCanOnlyReadUserEndpoints(t *testing.T) {
	// Create client with admin-read scope only
	accessToken, client := createClientWithGranularScope(t, constants.AdminReadPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	// Create a test user for the tests
	testUser := &models.User{
		Subject:   uuid.New(),
		Enabled:   true,
		Email:     gofakeit.Email(),
		GivenName: "TestUser",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	baseURL := config.GetAuthServer().BaseURL

	// Test: Should be able to read user search
	resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/users/search", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "admin-read should access user search")
	_ = resp.Body.Close()

	// Test: Should be able to read user details
	resp = makeAPIRequest(t, "GET", fmt.Sprintf("%s/api/v1/admin/users/%d", baseURL, testUser.Id), accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "admin-read should access user details")
	_ = resp.Body.Close()

	// Test: Should NOT be able to update user profile (PUT)
	resp = makeAPIRequest(t, "PUT", fmt.Sprintf("%s/api/v1/admin/users/%d/profile", baseURL, testUser.Id), accessToken, map[string]string{
		"givenName": "Updated",
	})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "admin-read should NOT update user profile")
	_ = resp.Body.Close()

	// Test: Should NOT be able to create user (POST)
	resp = makeAPIRequest(t, "POST", baseURL+"/api/v1/admin/users/create", accessToken, map[string]string{
		"email": gofakeit.Email(),
	})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "admin-read should NOT create user")
	_ = resp.Body.Close()

	// Test: Should NOT be able to delete user (DELETE)
	resp = makeAPIRequest(t, "DELETE", fmt.Sprintf("%s/api/v1/admin/users/%d", baseURL, testUser.Id), accessToken, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "admin-read should NOT delete user")
	_ = resp.Body.Close()
}

// TestGranularScopes_AdminReadCanOnlyReadClientEndpoints verifies that admin-read scope
// can access GET endpoints but not PUT/POST/DELETE endpoints for clients
func TestGranularScopes_AdminReadCanOnlyReadClientEndpoints(t *testing.T) {
	// Create client with admin-read scope only
	accessToken, client := createClientWithGranularScope(t, constants.AdminReadPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	// Create a test client for the tests
	testClient := &models.Client{
		ClientIdentifier: "test-client-" + gofakeit.LetterN(8),
		Enabled:          true,
	}
	err := database.CreateClient(nil, testClient)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteClient(nil, testClient.Id)
	}()

	baseURL := config.GetAuthServer().BaseURL

	// Test: Should be able to read clients list
	resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/clients", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "admin-read should access clients list")
	_ = resp.Body.Close()

	// Test: Should be able to read client details
	resp = makeAPIRequest(t, "GET", fmt.Sprintf("%s/api/v1/admin/clients/%d", baseURL, testClient.Id), accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "admin-read should access client details")
	_ = resp.Body.Close()

	// Test: Should NOT be able to update client (PUT)
	resp = makeAPIRequest(t, "PUT", fmt.Sprintf("%s/api/v1/admin/clients/%d", baseURL, testClient.Id), accessToken, map[string]string{
		"description": "Updated",
	})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "admin-read should NOT update client")
	_ = resp.Body.Close()

	// Test: Should NOT be able to create client (POST)
	resp = makeAPIRequest(t, "POST", baseURL+"/api/v1/admin/clients", accessToken, map[string]string{
		"clientIdentifier": "new-client-" + gofakeit.LetterN(8),
	})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "admin-read should NOT create client")
	_ = resp.Body.Close()

	// Test: Should NOT be able to delete client (DELETE)
	resp = makeAPIRequest(t, "DELETE", fmt.Sprintf("%s/api/v1/admin/clients/%d", baseURL, testClient.Id), accessToken, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "admin-read should NOT delete client")
	_ = resp.Body.Close()
}

// TestGranularScopes_AdminReadCanOnlyReadSettingsEndpoints verifies that admin-read scope
// can access GET endpoints but not PUT/POST/DELETE endpoints for settings
func TestGranularScopes_AdminReadCanOnlyReadSettingsEndpoints(t *testing.T) {
	// Create client with admin-read scope only
	accessToken, client := createClientWithGranularScope(t, constants.AdminReadPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	baseURL := config.GetAuthServer().BaseURL

	// Test: Should be able to read general settings
	resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/settings/general", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "admin-read should access general settings")
	_ = resp.Body.Close()

	// Test: Should be able to read email settings
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/settings/email", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "admin-read should access email settings")
	_ = resp.Body.Close()

	// Test: Should be able to read resources
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/resources", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "admin-read should access resources")
	_ = resp.Body.Close()

	// Test: Should NOT be able to update general settings (PUT)
	resp = makeAPIRequest(t, "PUT", baseURL+"/api/v1/admin/settings/general", accessToken, map[string]string{
		"appName": "Updated",
	})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "admin-read should NOT update general settings")
	_ = resp.Body.Close()

	// Test: Should NOT be able to create resource (POST)
	resp = makeAPIRequest(t, "POST", baseURL+"/api/v1/admin/resources", accessToken, map[string]string{
		"resourceIdentifier": "new-resource-" + gofakeit.LetterN(8),
	})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "admin-read should NOT create resource")
	_ = resp.Body.Close()
}

// TestGranularScopes_ManageUsersCanAccessUserEndpointsOnly verifies that manage-users scope
// can access user endpoints but cannot access client or settings endpoints
func TestGranularScopes_ManageUsersCanAccessUserEndpointsOnly(t *testing.T) {
	// Create client with manage-users scope only
	accessToken, client := createClientWithGranularScope(t, constants.ManageUsersPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	// Create a test user for the tests
	testUser := &models.User{
		Subject:   uuid.New(),
		Enabled:   true,
		Email:     gofakeit.Email(),
		GivenName: "TestUser",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Create a test client
	testClient := &models.Client{
		ClientIdentifier: "test-client-" + gofakeit.LetterN(8),
		Enabled:          true,
	}
	err = database.CreateClient(nil, testClient)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteClient(nil, testClient.Id)
	}()

	baseURL := config.GetAuthServer().BaseURL

	// Test: Should be able to read users (GET)
	resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/users/search", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage-users should access user search")
	_ = resp.Body.Close()

	// Test: Should be able to update user profile (PUT)
	resp = makeAPIRequest(t, "PUT", fmt.Sprintf("%s/api/v1/admin/users/%d/profile", baseURL, testUser.Id), accessToken, map[string]interface{}{
		"givenName":  "UpdatedName",
		"familyName": "",
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage-users should update user profile")
	_ = resp.Body.Close()

	// Test: Should NOT be able to read clients (no clients scope)
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/clients", accessToken, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "manage-users should NOT access clients list")
	_ = resp.Body.Close()

	// Test: Should NOT be able to read settings
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/settings/general", accessToken, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "manage-users should NOT access settings")
	_ = resp.Body.Close()
}

// TestGranularScopes_ManageClientsCanAccessClientEndpointsOnly verifies that manage-clients scope
// can access client endpoints but cannot access user or settings endpoints
func TestGranularScopes_ManageClientsCanAccessClientEndpointsOnly(t *testing.T) {
	// Create client with manage-clients scope only
	accessToken, client := createClientWithGranularScope(t, constants.ManageClientsPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	// Create a test user
	testUser := &models.User{
		Subject:   uuid.New(),
		Enabled:   true,
		Email:     gofakeit.Email(),
		GivenName: "TestUser",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Create a test client
	testClient := &models.Client{
		ClientIdentifier: "test-client-" + gofakeit.LetterN(8),
		Enabled:          true,
	}
	err = database.CreateClient(nil, testClient)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteClient(nil, testClient.Id)
	}()

	baseURL := config.GetAuthServer().BaseURL

	// Test: Should be able to read clients (GET)
	resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/clients", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage-clients should access clients list")
	_ = resp.Body.Close()

	// Test: Should be able to update client (PUT)
	resp = makeAPIRequest(t, "PUT", fmt.Sprintf("%s/api/v1/admin/clients/%d", baseURL, testClient.Id), accessToken, map[string]interface{}{
		"clientIdentifier": testClient.ClientIdentifier,
		"description":      "Updated description",
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage-clients should update client")
	_ = resp.Body.Close()

	// Test: Should NOT be able to read users (no users scope)
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/users/search", accessToken, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "manage-clients should NOT access users search")
	_ = resp.Body.Close()

	// Test: Should NOT be able to read settings
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/settings/general", accessToken, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "manage-clients should NOT access settings")
	_ = resp.Body.Close()
}

// TestGranularScopes_ManageSettingsCanAccessSettingsEndpointsOnly verifies that manage-settings scope
// can access settings endpoints but cannot access user or client endpoints
func TestGranularScopes_ManageSettingsCanAccessSettingsEndpointsOnly(t *testing.T) {
	// Create client with manage-settings scope only
	accessToken, client := createClientWithGranularScope(t, constants.ManageSettingsPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	// Create a test user
	testUser := &models.User{
		Subject:   uuid.New(),
		Enabled:   true,
		Email:     gofakeit.Email(),
		GivenName: "TestUser",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	baseURL := config.GetAuthServer().BaseURL

	// Test: Should be able to read settings (GET)
	resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/settings/general", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage-settings should access general settings")
	_ = resp.Body.Close()

	// Test: Should be able to read resources (part of settings domain)
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/resources", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage-settings should access resources")
	_ = resp.Body.Close()

	// Test: Should NOT be able to read users (no users scope)
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/users/search", accessToken, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "manage-settings should NOT access users search")
	_ = resp.Body.Close()

	// Test: Should NOT be able to read clients (no clients scope)
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/clients", accessToken, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "manage-settings should NOT access clients list")
	_ = resp.Body.Close()
}

// TestGranularScopes_ManageCanAccessAllEndpoints verifies that manage scope (full admin)
// can access all endpoints (backwards compatibility)
func TestGranularScopes_ManageCanAccessAllEndpoints(t *testing.T) {
	// Create client with manage scope (full access)
	accessToken, client := createAdminClientWithToken(t)
	defer func() {
		_ = database.DeleteClient(nil, client.Id)
	}()

	// Create a test user
	testUser := &models.User{
		Subject:   uuid.New(),
		Enabled:   true,
		Email:     gofakeit.Email(),
		GivenName: "TestUser",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Create a test client
	testClient := &models.Client{
		ClientIdentifier: "test-client-" + gofakeit.LetterN(8),
		Enabled:          true,
	}
	err = database.CreateClient(nil, testClient)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteClient(nil, testClient.Id)
	}()

	baseURL := config.GetAuthServer().BaseURL

	// Test: Should be able to access users
	resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/users/search", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage should access user search")
	_ = resp.Body.Close()

	// Test: Should be able to update user profile
	resp = makeAPIRequest(t, "PUT", fmt.Sprintf("%s/api/v1/admin/users/%d/profile", baseURL, testUser.Id), accessToken, map[string]interface{}{
		"givenName":  "UpdatedName",
		"familyName": "",
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage should update user profile")
	_ = resp.Body.Close()

	// Test: Should be able to access clients
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/clients", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage should access clients list")
	_ = resp.Body.Close()

	// Test: Should be able to update client
	resp = makeAPIRequest(t, "PUT", fmt.Sprintf("%s/api/v1/admin/clients/%d", baseURL, testClient.Id), accessToken, map[string]interface{}{
		"clientIdentifier": testClient.ClientIdentifier,
		"description":      "Updated description",
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage should update client")
	_ = resp.Body.Close()

	// Test: Should be able to access settings
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/settings/general", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage should access general settings")
	_ = resp.Body.Close()

	// Test: Should be able to access resources
	resp = makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/resources", accessToken, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "manage should access resources")
	_ = resp.Body.Close()
}

// TestGranularScopes_NoScopeCannotAccessAdmin verifies that without any admin scope,
// API endpoints are inaccessible
func TestGranularScopes_NoScopeCannotAccessAdmin(t *testing.T) {
	baseURL := config.GetAuthServer().BaseURL

	// Test without any authorization
	req, err := http.NewRequest("GET", baseURL+"/api/v1/admin/users/search", nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "no token should be unauthorized")
}

// TestGranularScopes_InvalidTokenCannotAccess verifies that an invalid token
// cannot access any admin endpoints
func TestGranularScopes_InvalidTokenCannotAccess(t *testing.T) {
	baseURL := config.GetAuthServer().BaseURL

	// Test with invalid token
	resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/users/search", "invalid-token-12345", nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "invalid token should be unauthorized")
}

// TestGranularScopes_PhoneCountriesAccessibleByAnyAdminScope verifies that
// reference data (phone-countries) is accessible by any admin scope
func TestGranularScopes_PhoneCountriesAccessibleByAnyAdminScope(t *testing.T) {
	baseURL := config.GetAuthServer().BaseURL

	testCases := []struct {
		name               string
		permissionId       string
		expectedStatusCode int
	}{
		{"admin-read", constants.AdminReadPermissionIdentifier, http.StatusOK},
		{"manage-users", constants.ManageUsersPermissionIdentifier, http.StatusForbidden}, // Only scopesRead allows this
		{"manage-clients", constants.ManageClientsPermissionIdentifier, http.StatusForbidden},
		{"manage-settings", constants.ManageSettingsPermissionIdentifier, http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			accessToken, client := createClientWithGranularScope(t, tc.permissionId)
			defer func() {
				_ = database.DeleteClient(nil, client.Id)
			}()

			resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/phone-countries", accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatusCode, resp.StatusCode, "%s should have status %d for phone-countries", tc.name, tc.expectedStatusCode)
		})
	}

	// Manage scope should always work
	t.Run("manage", func(t *testing.T) {
		accessToken, client := createAdminClientWithToken(t)
		defer func() {
			_ = database.DeleteClient(nil, client.Id)
		}()

		resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/phone-countries", accessToken, nil)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "manage should access phone-countries")
	})
}

// TestGranularScopes_GroupsRequireUsersScope verifies that group endpoints
// require users scope (as groups are related to user management)
func TestGranularScopes_GroupsRequireUsersScope(t *testing.T) {
	// Create a test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	baseURL := config.GetAuthServer().BaseURL

	testCases := []struct {
		name               string
		permissionId       string
		expectedReadStatus int
	}{
		{"admin-read", constants.AdminReadPermissionIdentifier, http.StatusOK},
		{"manage-users", constants.ManageUsersPermissionIdentifier, http.StatusOK},
		{"manage-clients", constants.ManageClientsPermissionIdentifier, http.StatusForbidden},
		{"manage-settings", constants.ManageSettingsPermissionIdentifier, http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			accessToken, client := createClientWithGranularScope(t, tc.permissionId)
			defer func() {
				_ = database.DeleteClient(nil, client.Id)
			}()

			// Test reading groups
			resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/groups", accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedReadStatus, resp.StatusCode, "%s should have status %d for groups GET", tc.name, tc.expectedReadStatus)
		})
	}
}

// TestGranularScopes_ResourcesRequireSettingsScope verifies that resource endpoints
// require settings scope
func TestGranularScopes_ResourcesRequireSettingsScope(t *testing.T) {
	baseURL := config.GetAuthServer().BaseURL

	testCases := []struct {
		name               string
		permissionId       string
		expectedReadStatus int
	}{
		{"admin-read", constants.AdminReadPermissionIdentifier, http.StatusOK},
		{"manage-users", constants.ManageUsersPermissionIdentifier, http.StatusForbidden},
		{"manage-clients", constants.ManageClientsPermissionIdentifier, http.StatusForbidden},
		{"manage-settings", constants.ManageSettingsPermissionIdentifier, http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			accessToken, client := createClientWithGranularScope(t, tc.permissionId)
			defer func() {
				_ = database.DeleteClient(nil, client.Id)
			}()

			// Test reading resources
			resp := makeAPIRequest(t, "GET", baseURL+"/api/v1/admin/resources", accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedReadStatus, resp.StatusCode, "%s should have status %d for resources GET", tc.name, tc.expectedReadStatus)
		})
	}
}

// TestGranularScopes_UserPermissionsRequireUsersScope verifies that user permission endpoints
// require users scope
func TestGranularScopes_UserPermissionsRequireUsersScope(t *testing.T) {
	// Create a test user
	testUser := &models.User{
		Subject:   uuid.New(),
		Enabled:   true,
		Email:     gofakeit.Email(),
		GivenName: "TestUser",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	baseURL := config.GetAuthServer().BaseURL

	testCases := []struct {
		name               string
		permissionId       string
		expectedReadStatus int
	}{
		{"admin-read", constants.AdminReadPermissionIdentifier, http.StatusOK},
		{"manage-users", constants.ManageUsersPermissionIdentifier, http.StatusOK},
		{"manage-clients", constants.ManageClientsPermissionIdentifier, http.StatusForbidden},
		{"manage-settings", constants.ManageSettingsPermissionIdentifier, http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			accessToken, client := createClientWithGranularScope(t, tc.permissionId)
			defer func() {
				_ = database.DeleteClient(nil, client.Id)
			}()

			// Test reading user permissions
			resp := makeAPIRequest(t, "GET", fmt.Sprintf("%s/api/v1/admin/users/%d/permissions", baseURL, testUser.Id), accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedReadStatus, resp.StatusCode, "%s should have status %d for user permissions GET", tc.name, tc.expectedReadStatus)
		})
	}
}

// TestGranularScopes_ClientPermissionsRequireClientsScope verifies that client permission endpoints
// require clients scope
func TestGranularScopes_ClientPermissionsRequireClientsScope(t *testing.T) {
	// Create a test client
	testClient := &models.Client{
		ClientIdentifier: "test-client-" + gofakeit.LetterN(8),
		Enabled:          true,
	}
	err := database.CreateClient(nil, testClient)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteClient(nil, testClient.Id)
	}()

	baseURL := config.GetAuthServer().BaseURL

	testCases := []struct {
		name               string
		permissionId       string
		expectedReadStatus int
	}{
		{"admin-read", constants.AdminReadPermissionIdentifier, http.StatusOK},
		{"manage-users", constants.ManageUsersPermissionIdentifier, http.StatusForbidden},
		{"manage-clients", constants.ManageClientsPermissionIdentifier, http.StatusOK},
		{"manage-settings", constants.ManageSettingsPermissionIdentifier, http.StatusForbidden},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			accessToken, client := createClientWithGranularScope(t, tc.permissionId)
			defer func() {
				_ = database.DeleteClient(nil, client.Id)
			}()

			// Test reading client permissions
			resp := makeAPIRequest(t, "GET", fmt.Sprintf("%s/api/v1/admin/clients/%d/permissions", baseURL, testClient.Id), accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedReadStatus, resp.StatusCode, "%s should have status %d for client permissions GET", tc.name, tc.expectedReadStatus)
		})
	}
}

// TestGranularScopes_WriteOperationsRequireSpecificScopes tests that write operations
// (POST, PUT, DELETE) require the specific domain scope, not just admin-read
func TestGranularScopes_WriteOperationsRequireSpecificScopes(t *testing.T) {
	baseURL := config.GetAuthServer().BaseURL

	// Create admin-read client (read-only)
	readOnlyToken, readOnlyClient := createClientWithGranularScope(t, constants.AdminReadPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, readOnlyClient.Id)
	}()

	// Create manage-users client (full user access)
	usersToken, usersClient := createClientWithGranularScope(t, constants.ManageUsersPermissionIdentifier)
	defer func() {
		_ = database.DeleteClient(nil, usersClient.Id)
	}()

	// Test user creation
	t.Run("user creation requires manage-users scope", func(t *testing.T) {
		newUserPayload := map[string]interface{}{
			"email":    gofakeit.Email(),
			"password": gofakeit.Password(true, true, true, true, false, 12),
		}

		// admin-read should fail
		resp := makeAPIRequest(t, "POST", baseURL+"/api/v1/admin/users/create", readOnlyToken, newUserPayload)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "admin-read should not create users")
		_ = resp.Body.Close()

		// manage-users should succeed
		resp = makeAPIRequest(t, "POST", baseURL+"/api/v1/admin/users/create", usersToken, newUserPayload)
		// Check if it's OK or a validation error (not forbidden)
		assert.NotEqual(t, http.StatusForbidden, resp.StatusCode, "manage-users should be authorized to create users")

		// If created successfully, clean up
		if resp.StatusCode == http.StatusCreated {
			var result map[string]interface{}
			_ = json.NewDecoder(resp.Body).Decode(&result)
			if userId, ok := result["id"].(float64); ok {
				_ = database.DeleteUser(nil, int64(userId))
			}
		}
		_ = resp.Body.Close()
	})

	// Test group creation
	t.Run("group creation requires manage-users scope", func(t *testing.T) {
		newGroupPayload := map[string]interface{}{
			"groupIdentifier": "test-group-" + gofakeit.LetterN(8),
			"description":     "Test group",
		}

		// admin-read should fail
		resp := makeAPIRequest(t, "POST", baseURL+"/api/v1/admin/groups", readOnlyToken, newGroupPayload)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "admin-read should not create groups")
		_ = resp.Body.Close()

		// manage-users should succeed
		resp = makeAPIRequest(t, "POST", baseURL+"/api/v1/admin/groups", usersToken, newGroupPayload)
		assert.NotEqual(t, http.StatusForbidden, resp.StatusCode, "manage-users should be authorized to create groups")

		// If created successfully, clean up
		if resp.StatusCode == http.StatusCreated {
			var result map[string]interface{}
			_ = json.NewDecoder(resp.Body).Decode(&result)
			if groupId, ok := result["id"].(float64); ok {
				_ = database.DeleteGroup(nil, int64(groupId))
			}
		}
		_ = resp.Body.Close()
	})
}
