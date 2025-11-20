package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIUserPermissionsGet tests the GET /api/v1/admin/users/{id}/permissions endpoint
func TestAPIUserPermissionsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@permissions.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "test-resource", "Test Resource")
	defer func() {
		_ = database.DeleteResource(nil, resource.Id)
	}()

	perm1 := createTestPermission(t, resource.Id, "read", "Read permission")
	perm2 := createTestPermission(t, resource.Id, "write", "Write permission")
	defer func() {
		_ = database.DeletePermission(nil, perm1.Id)
		_ = database.DeletePermission(nil, perm2.Id)
	}()

	// Setup: Assign permissions to user
	userPerm1 := createTestUserPermission(t, testUser.Id, perm1.Id)
	userPerm2 := createTestUserPermission(t, testUser.Id, perm2.Id)
	defer func() {
		_ = database.DeleteUserPermission(nil, userPerm1.Id)
		_ = database.DeleteUserPermission(nil, userPerm2.Id)
	}()

	// Test: Get user permissions
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetUserPermissionsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: User information
	assert.Equal(t, testUser.Id, getResponse.User.Id)
	assert.Equal(t, testUser.Email, getResponse.User.Email)

	// Assert: Should return both permissions with resource info
	assert.Len(t, getResponse.Permissions, 2)

	// Create map for easier assertion
	permMap := make(map[string]api.PermissionResponse)
	for _, perm := range getResponse.Permissions {
		permMap[perm.PermissionIdentifier] = perm
	}

	// Verify permissions with embedded resource info
	readPerm, exists := permMap["read"]
	assert.True(t, exists)
	assert.Equal(t, "Read permission", readPerm.Description)
	assert.Equal(t, resource.Id, readPerm.ResourceId)
	assert.Equal(t, "test-resource", readPerm.Resource.ResourceIdentifier)
	assert.Equal(t, "Test Resource", readPerm.Resource.Description)

	writePerm, exists := permMap["write"]
	assert.True(t, exists)
	assert.Equal(t, "Write permission", writePerm.Description)
	assert.Equal(t, resource.Id, writePerm.ResourceId)
	assert.Equal(t, "test-resource", writePerm.Resource.ResourceIdentifier)
}

func TestAPIUserPermissionsGet_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get permissions for non-existent user
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserPermissionsGet_InvalidUserId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get permissions with invalid user ID
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/invalid/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 400
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserPermissionsGet_NoPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without permissions
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@no-permissions.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Get user permissions for user with no permissions
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetUserPermissionsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return empty permissions array
	assert.Len(t, getResponse.Permissions, 0)
	assert.Equal(t, testUser.Id, getResponse.User.Id)
}

func TestAPIUserPermissionsGet_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth-permissions.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/permissions"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserPermissionsPut tests the PUT /api/v1/admin/users/{id}/permissions endpoint
func TestAPIUserPermissionsPut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@permissions-put.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "put-test-resource", "PUT Test Resource")
	defer func() {
		_ = database.DeleteResource(nil, resource.Id)
	}()

	perm1 := createTestPermission(t, resource.Id, "read", "Read permission")
	perm2 := createTestPermission(t, resource.Id, "write", "Write permission")
	perm3 := createTestPermission(t, resource.Id, "delete", "Delete permission")
	defer func() {
		_ = database.DeletePermission(nil, perm1.Id)
		_ = database.DeletePermission(nil, perm2.Id)
		_ = database.DeletePermission(nil, perm3.Id)
	}()

	// Setup: Initially assign one permission
	initialUserPerm := createTestUserPermission(t, testUser.Id, perm1.Id)
	defer func() {
		_ = database.DeleteUserPermission(nil, initialUserPerm.Id)
	}()

	// Test: Update user permissions (replace with two different permissions)
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIds: []int64{perm2.Id, perm3.Id},
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)
	assert.True(t, updateResponse.Success)

	// Verify changes were persisted: Load user permissions
	err = database.UserLoadPermissions(nil, testUser)
	assert.NoError(t, err)

	// Assert: Should have exactly 2 permissions (perm2 and perm3)
	assert.Len(t, testUser.Permissions, 2)

	permIds := make([]int64, len(testUser.Permissions))
	for i, perm := range testUser.Permissions {
		permIds[i] = perm.Id
	}

	assert.Contains(t, permIds, perm2.Id)
	assert.Contains(t, permIds, perm3.Id)
	assert.NotContains(t, permIds, perm1.Id) // Should be removed
}

func TestAPIUserPermissionsPut_RemoveAllPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@remove-all-permissions.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test resource and permission
	resource := createTestResource(t, "remove-test-resource", "Remove Test Resource")
	defer func() {
		_ = database.DeleteResource(nil, resource.Id)
	}()

	perm := createTestPermission(t, resource.Id, "test-perm", "Test permission")
	defer func() {
		_ = database.DeletePermission(nil, perm.Id)
	}()

	// Setup: Assign permission to user
	userPerm := createTestUserPermission(t, testUser.Id, perm.Id)

	// Test: Remove all permissions (empty array)
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIds: []int64{},
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)
	assert.True(t, updateResponse.Success)

	// Verify permission was removed
	err = database.UserLoadPermissions(nil, testUser)
	assert.NoError(t, err)
	assert.Len(t, testUser.Permissions, 0)

	// Verify the UserPermission record was deleted
	deletedUserPerm, err := database.GetUserPermissionById(nil, userPerm.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedUserPerm)
}

func TestAPIUserPermissionsPut_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update permissions for non-existent user
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIds: []int64{},
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserPermissionsPut_PermissionNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@perm-not-found.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update with non-existent permission
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIds: []int64{99999},
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserPermissionsPut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@invalid-body.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/permissions"
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserPermissionsPut_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth-put.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/permissions"
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// Helper function to create a user permission
func createTestUserPermission(t *testing.T, userId, permissionId int64) *models.UserPermission {
	userPermission := &models.UserPermission{
		UserId:       userId,
		PermissionId: permissionId,
	}
	err := database.CreateUserPermission(nil, userPermission)
	assert.NoError(t, err)
	return userPermission
}
