package integrationtests

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIUserPermissionsGet tests the GET /api/v1/admin/users/{id}/permissions endpoint
func TestAPIUserPermissionsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@permissions.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "test-resource", "Test Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	perm1 := createTestPermission(t, resource.Id, "read", "Read permission")
	perm2 := createTestPermission(t, resource.Id, "write", "Write permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm1.Id)
		_ = database.DeletePermission(context.Background(), nil, perm2.Id)
	}()

	// Setup: Assign permissions to user
	userPerm1 := createTestUserPermission(t, testUser.Id, perm1.Id)
	userPerm2 := createTestUserPermission(t, testUser.Id, perm2.Id)
	defer func() {
		_ = database.DeleteUserPermission(context.Background(), nil, userPerm1.Id)
		_ = database.DeleteUserPermission(context.Background(), nil, userPerm2.Id)
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
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@no-permissions.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
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
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@unauth-permissions.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
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
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@permissions-put.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "put-test-resource", "PUT Test Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	perm1 := createTestPermission(t, resource.Id, "read", "Read permission")
	perm2 := createTestPermission(t, resource.Id, "write", "Write permission")
	perm3 := createTestPermission(t, resource.Id, "delete", "Delete permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm1.Id)
		_ = database.DeletePermission(context.Background(), nil, perm2.Id)
		_ = database.DeletePermission(context.Background(), nil, perm3.Id)
	}()

	// Setup: Initially assign one permission
	initialUserPerm := createTestUserPermission(t, testUser.Id, perm1.Id)
	defer func() {
		_ = database.DeleteUserPermission(context.Background(), nil, initialUserPerm.Id)
	}()

	// Test: Update user permissions (replace with two different permissions)
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIds:         []int64{perm2.Id, perm3.Id},
		ExpectedPermissionIds: getUserPermissionIds(t, accessToken, testUser.Id),
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
	err = database.UserLoadPermissions(context.Background(), nil, testUser)
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
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@remove-all-permissions.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Setup: Create test resource and permission
	resource := createTestResource(t, "remove-test-resource", "Remove Test Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	perm := createTestPermission(t, resource.Id, "test-perm", "Test permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm.Id)
	}()

	// Setup: Assign permission to user
	userPerm := createTestUserPermission(t, testUser.Id, perm.Id)

	// Test: Remove all permissions (empty array)
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIds:         []int64{},
		ExpectedPermissionIds: getUserPermissionIds(t, accessToken, testUser.Id),
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
	err = database.UserLoadPermissions(context.Background(), nil, testUser)
	assert.NoError(t, err)
	assert.Len(t, testUser.Permissions, 0)

	// Verify the UserPermission record was deleted
	deletedUserPerm, err := database.GetUserPermissionById(context.Background(), nil, userPerm.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedUserPerm)
}

func TestAPIUserPermissionsPut_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update permissions for non-existent user, whose grants cannot be read
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIds:         []int64{},
		ExpectedPermissionIds: []int64{},
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
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@perm-not-found.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Test: Update with non-existent permission
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIds:         []int64{99999},
		ExpectedPermissionIds: getUserPermissionIds(t, accessToken, testUser.Id),
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
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@invalid-body.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
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
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@unauth-put.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
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
	err := database.CreateUserPermission(context.Background(), nil, userPermission)
	assert.NoError(t, err)
	return userPermission
}

// getUserPermissionIds reads the user's grants through the API, as a caller does before a save,
// and returns their ids: the loaded set a save carries (#428).
func getUserPermissionIds(t *testing.T, accessToken string, userId int64) []int64 {
	t.Helper()
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(userId, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.GetUserPermissionsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	ids := []int64{}
	for _, p := range body.Permissions {
		ids = append(ids, p.Id)
	}
	return ids
}

// newPermissionsTestUser creates a user for one save test and deletes it after.
func newPermissionsTestUser(t *testing.T, emailPrefix string) *models.User {
	t.Helper()
	user := &models.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail(emailPrefix + "@user-permissions.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	return user
}

// The loaded set is required: absent or null answers 400 naming the field, and nothing is granted
// (#428).
func TestAPIUserPermissionsPut_TheLoadedListIsRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := newPermissionsTestUser(t, "expected-required")
	resource := createTestResource(t, "user-perm-expected-"+fake.UUID()[:8], "User permission expected resource")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) })
	perm := createTestPermission(t, resource.Id, "read", "Read permission")
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/permissions"

	bodies := map[string]interface{}{
		"absent": map[string]interface{}{"permissionIds": []int64{perm.Id}},
		"null":   map[string]interface{}{"permissionIds": []int64{perm.Id}, "expectedPermissionIds": nil},
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			resp := makeAPIRequest(t, "PUT", url, accessToken, body)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var got map[string]interface{}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
			assert.Equal(t, "VALIDATION_ERROR", got["error_code"])
			assert.Contains(t, got["error_description"], "expectedPermissionIds is required")
			assert.Empty(t, getUserPermissionIds(t, accessToken, user.Id))
		})
	}
}

// Two administrators load the same grants; the first revokes one, and the second, still holding
// the set as it was, saves. The second is refused 409 CONCURRENT_UPDATE and writes nothing, where it
// used to write its whole set and silently re-grant the permission the first had just revoked
// (#428).
func TestAPIUserPermissionsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := newPermissionsTestUser(t, "expected-outdated")
	resource := createTestResource(t, "user-perm-outdated-"+fake.UUID()[:8], "User permission outdated resource")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) })
	permA := createTestPermission(t, resource.Id, "read", "Read permission")
	permB := createTestPermission(t, resource.Id, "write", "Write permission")
	permC := createTestPermission(t, resource.Id, "delete", "Delete permission")
	createTestUserPermission(t, user.Id, permA.Id)
	createTestUserPermission(t, user.Id, permB.Id)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/permissions"

	loadedByBoth := getUserPermissionIds(t, accessToken, user.Id)

	first := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserPermissionsRequest{
		PermissionIds: []int64{permB.Id}, ExpectedPermissionIds: loadedByBoth})
	defer func() { _ = first.Body.Close() }()
	require.Equal(t, http.StatusOK, first.StatusCode)

	second := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserPermissionsRequest{
		PermissionIds: []int64{permA.Id, permB.Id, permC.Id}, ExpectedPermissionIds: loadedByBoth})
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusConflict, second.StatusCode)
	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(second.Body).Decode(&body))
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
	assert.Contains(t, body["error_description"], "reload it")

	assert.Equal(t, []int64{permB.Id}, getUserPermissionIds(t, accessToken, user.Id), "the refused save wrote nothing")
}

// A save naming one permission twice grants it once, so a following save without it revokes it
// entirely. The save used to insert both, and the revocation deleted one of the two rows and left
// the permission granted, which the read after it would still show (#406).
func TestAPIUserPermissionsPut_ARepeatedIdIsGrantedOnceAndRevokedWhole(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := newPermissionsTestUser(t, "repeated-id")
	resource := createTestResource(t, "user-perm-repeat-"+fake.UUID()[:8], "User permission repeat resource")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) })
	perm := createTestPermission(t, resource.Id, "read", "Read permission")
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/permissions"

	grant := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserPermissionsRequest{
		PermissionIds: []int64{perm.Id, perm.Id}, ExpectedPermissionIds: []int64{}})
	defer func() { _ = grant.Body.Close() }()
	require.Equal(t, http.StatusOK, grant.StatusCode)
	loaded := getUserPermissionIds(t, accessToken, user.Id)
	require.Equal(t, []int64{perm.Id}, loaded)

	revoke := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserPermissionsRequest{
		PermissionIds: []int64{}, ExpectedPermissionIds: loaded})
	defer func() { _ = revoke.Body.Close() }()
	require.Equal(t, http.StatusOK, revoke.StatusCode)
	assert.Empty(t, getUserPermissionIds(t, accessToken, user.Id), "no copy of the grant is left")
}
