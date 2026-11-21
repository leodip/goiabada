package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIUserPermissionsGet tests the GET /api/v1/admin/users/{id}/permissions endpoint
func TestAPIUserPermissionsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@permissions.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "test-resource", "Test Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.ID)
	}()

	perm1 := createTestPermission(t, resource.ID, "read", "Read permission")
	perm2 := createTestPermission(t, resource.ID, "write", "Write permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm1.ID)
		_ = database.DeletePermission(context.Background(), nil, perm2.ID)
	}()

	// Setup: Assign permissions to user
	userPerm1 := createTestUserPermission(t, testUser.ID, perm1.ID)
	userPerm2 := createTestUserPermission(t, testUser.ID, perm2.ID)
	defer func() {
		_ = database.DeleteUserPermission(context.Background(), nil, userPerm1.ID)
		_ = database.DeleteUserPermission(context.Background(), nil, userPerm2.ID)
	}()

	// Test: Get user permissions
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetUserPermissionsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: User information
	assert.Equal(t, testUser.ID, getResponse.User.ID)
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
	assert.Equal(t, resource.ID, readPerm.ResourceID)
	assert.Equal(t, "test-resource", readPerm.Resource.ResourceIdentifier)
	assert.Equal(t, "Test Resource", readPerm.Resource.Description)

	writePerm, exists := permMap["write"]
	assert.True(t, exists)
	assert.Equal(t, "Write permission", writePerm.Description)
	assert.Equal(t, resource.ID, writePerm.ResourceID)
	assert.Equal(t, "test-resource", writePerm.Resource.ResourceIdentifier)
}

func TestAPIUserPermissionsGet_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get permissions for non-existent user
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/99999/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserPermissionsGet_InvalidUserID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get permissions with invalid user ID
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/invalid/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 400
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserPermissionsGet_NoPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without permissions
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@no-permissions.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Get user permissions for user with no permissions
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetUserPermissionsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: Should return empty permissions array
	assert.Empty(t, getResponse.Permissions)
	assert.Equal(t, testUser.ID, getResponse.User.ID)
}

func TestAPIUserPermissionsGet_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@unauth-permissions.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/permissions"
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserPermissionsPut tests the PUT /api/v1/admin/users/{id}/permissions endpoint
func TestAPIUserPermissionsPut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@permissions-put.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "put-test-resource", "PUT Test Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.ID)
	}()

	perm1 := createTestPermission(t, resource.ID, "read", "Read permission")
	perm2 := createTestPermission(t, resource.ID, "write", "Write permission")
	perm3 := createTestPermission(t, resource.ID, "delete", "Delete permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm1.ID)
		_ = database.DeletePermission(context.Background(), nil, perm2.ID)
		_ = database.DeletePermission(context.Background(), nil, perm3.ID)
	}()

	// Setup: Initially assign one permission
	initialUserPerm := createTestUserPermission(t, testUser.ID, perm1.ID)
	defer func() {
		_ = database.DeleteUserPermission(context.Background(), nil, initialUserPerm.ID)
	}()

	// Test: Update user permissions (replace with two different permissions)
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIDs:         []int64{perm2.ID, perm3.ID},
		ExpectedPermissionIDs: getUserPermissionIDs(t, accessToken, testUser.ID),
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)
	assert.True(t, updateResponse.Success)

	// Verify changes were persisted: Load user permissions
	err = database.UserLoadPermissions(context.Background(), nil, testUser)
	require.NoError(t, err)

	// Assert: Should have exactly 2 permissions (perm2 and perm3)
	assert.Len(t, testUser.Permissions, 2)

	permIDs := make([]int64, len(testUser.Permissions))
	for i, perm := range testUser.Permissions {
		permIDs[i] = perm.ID
	}

	assert.Contains(t, permIDs, perm2.ID)
	assert.Contains(t, permIDs, perm3.ID)
	assert.NotContains(t, permIDs, perm1.ID) // Should be removed
}

func TestAPIUserPermissionsPut_RemoveAllPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@remove-all-permissions.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test resource and permission
	resource := createTestResource(t, "remove-test-resource", "Remove Test Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.ID)
	}()

	perm := createTestPermission(t, resource.ID, "test-perm", "Test permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm.ID)
	}()

	// Setup: Assign permission to user
	userPerm := createTestUserPermission(t, testUser.ID, perm.ID)

	// Test: Remove all permissions (empty array)
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIDs:         []int64{},
		ExpectedPermissionIDs: getUserPermissionIDs(t, accessToken, testUser.ID),
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)
	assert.True(t, updateResponse.Success)

	// Verify permission was removed
	err = database.UserLoadPermissions(context.Background(), nil, testUser)
	require.NoError(t, err)
	assert.Empty(t, testUser.Permissions)

	// Verify the UserPermission record was deleted
	deletedUserPerm, err := database.GetUserPermissionByID(context.Background(), nil, userPerm.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedUserPerm)
}

func TestAPIUserPermissionsPut_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update permissions for non-existent user, whose grants cannot be read
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIDs:         []int64{},
		ExpectedPermissionIDs: []int64{},
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/99999/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserPermissionsPut_PermissionNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@perm-not-found.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Update with non-existent permission
	updateReq := api.UpdateUserPermissionsRequest{
		PermissionIDs:         []int64{99999},
		ExpectedPermissionIDs: getUserPermissionIDs(t, accessToken, testUser.ID),
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserPermissionsPut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@invalid-body.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Invalid JSON
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/permissions"
	req, err := http.NewRequest("PUT", url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserPermissionsPut_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@unauth-put.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/permissions"
	req, err := http.NewRequest("PUT", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// Helper function to create a user permission
func createTestUserPermission(t *testing.T, userID, permissionID int64) *record.UserPermission {
	userPermission := &record.UserPermission{
		UserID:       userID,
		PermissionID: permissionID,
	}
	err := database.CreateUserPermission(context.Background(), nil, userPermission)
	assert.NoError(t, err)
	return userPermission
}

// getUserPermissionIDs reads the user's grants through the API, as a caller does before a save,
// and returns their ids: the loaded set a save carries (#428).
func getUserPermissionIDs(t *testing.T, accessToken string, userID int64) []int64 {
	t.Helper()
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(userID, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.GetUserPermissionsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	ids := []int64{}
	for _, p := range body.Permissions {
		ids = append(ids, p.ID)
	}
	return ids
}

// newPermissionsTestUser creates a user for one save test and deletes it after.
func newPermissionsTestUser(t *testing.T, emailPrefix string) *record.User {
	t.Helper()
	user := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail(emailPrefix + "@user-permissions.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.ID) })
	return user
}

// The loaded set is required: absent or null answers 400 naming the field, and nothing is granted
// (#428).
func TestAPIUserPermissionsPut_TheLoadedListIsRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := newPermissionsTestUser(t, "expected-required")
	resource := createTestResource(t, "user-perm-expected-"+fake.UUID()[:8], "User permission expected resource")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.ID) })
	perm := createTestPermission(t, resource.ID, "read", "Read permission")
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.ID, 10) + "/permissions"

	bodies := map[string]interface{}{
		"absent": map[string]interface{}{"permissionIDs": []int64{perm.ID}},
		"null":   map[string]interface{}{"permissionIDs": []int64{perm.ID}, "expectedPermissionIds": nil},
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
			assert.Empty(t, getUserPermissionIDs(t, accessToken, user.ID))
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
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.ID) })
	permA := createTestPermission(t, resource.ID, "read", "Read permission")
	permB := createTestPermission(t, resource.ID, "write", "Write permission")
	permC := createTestPermission(t, resource.ID, "delete", "Delete permission")
	createTestUserPermission(t, user.ID, permA.ID)
	createTestUserPermission(t, user.ID, permB.ID)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.ID, 10) + "/permissions"

	loadedByBoth := getUserPermissionIDs(t, accessToken, user.ID)

	first := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserPermissionsRequest{
		PermissionIDs: []int64{permB.ID}, ExpectedPermissionIDs: loadedByBoth})
	defer func() { _ = first.Body.Close() }()
	require.Equal(t, http.StatusOK, first.StatusCode)

	second := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserPermissionsRequest{
		PermissionIDs: []int64{permA.ID, permB.ID, permC.ID}, ExpectedPermissionIDs: loadedByBoth})
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusConflict, second.StatusCode)
	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(second.Body).Decode(&body))
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
	assert.Contains(t, body["error_description"], "reload it")

	assert.Equal(t, []int64{permB.ID}, getUserPermissionIDs(t, accessToken, user.ID), "the refused save wrote nothing")
}

// A save naming one permission twice grants it once, so a following save without it revokes it
// entirely. The save used to insert both, and the revocation deleted one of the two rows and left
// the permission granted, which the read after it would still show (#406).
func TestAPIUserPermissionsPut_ARepeatedIDIsGrantedOnceAndRevokedWhole(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	user := newPermissionsTestUser(t, "repeated-id")
	resource := createTestResource(t, "user-perm-repeat-"+fake.UUID()[:8], "User permission repeat resource")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.ID) })
	perm := createTestPermission(t, resource.ID, "read", "Read permission")
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.ID, 10) + "/permissions"

	grant := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserPermissionsRequest{
		PermissionIDs: []int64{perm.ID, perm.ID}, ExpectedPermissionIDs: []int64{}})
	defer func() { _ = grant.Body.Close() }()
	require.Equal(t, http.StatusOK, grant.StatusCode)
	loaded := getUserPermissionIDs(t, accessToken, user.ID)
	require.Equal(t, []int64{perm.ID}, loaded)

	revoke := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateUserPermissionsRequest{
		PermissionIDs: []int64{}, ExpectedPermissionIDs: loaded})
	defer func() { _ = revoke.Body.Close() }()
	require.Equal(t, http.StatusOK, revoke.StatusCode)
	assert.Empty(t, getUserPermissionIDs(t, accessToken, user.ID), "no copy of the grant is left")
}
