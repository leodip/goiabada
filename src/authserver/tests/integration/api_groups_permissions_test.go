package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIGroupPermissionsGet tests the GET /api/v1/admin/groups/{id}/permissions endpoint
func TestAPIGroupPermissionsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "test-group-resource", "Test Group Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.ID)
	}()

	perm1 := createTestPermission(t, resource.ID, "read", "Read permission")
	perm2 := createTestPermission(t, resource.ID, "write", "Write permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm1.ID)
		_ = database.DeletePermission(context.Background(), nil, perm2.ID)
	}()

	// Setup: Assign permissions to group
	groupPerm1 := createTestGroupPermission(t, testGroup.ID, perm1.ID)
	groupPerm2 := createTestGroupPermission(t, testGroup.ID, perm2.ID)
	defer func() {
		_ = database.DeleteGroupPermission(context.Background(), nil, groupPerm1.ID)
		_ = database.DeleteGroupPermission(context.Background(), nil, groupPerm2.ID)
	}()

	// Test: Get group permissions
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetGroupPermissionsResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: Group information
	assert.Equal(t, testGroup.ID, getResponse.Group.ID)
	assert.Equal(t, testGroup.GroupIdentifier, getResponse.Group.GroupIdentifier)

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
	assert.Equal(t, "test-group-resource", readPerm.Resource.ResourceIdentifier)
	assert.Equal(t, "Test Group Resource", readPerm.Resource.Description)

	writePerm, exists := permMap["write"]
	assert.True(t, exists)
	assert.Equal(t, "Write permission", writePerm.Description)
	assert.Equal(t, resource.ID, writePerm.ResourceID)
	assert.Equal(t, "test-group-resource", writePerm.Resource.ResourceIdentifier)
}

func TestAPIGroupPermissionsGet_GroupNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get permissions for non-existent group
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/99999/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupPermissionsGet_InvalidGroupID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get permissions with invalid group ID
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/invalid/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 400
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIGroupPermissionsGet_NoPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group without permissions
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Get group permissions for group with no permissions
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetGroupPermissionsResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: Should return empty permissions array
	assert.Empty(t, getResponse.Permissions)
	assert.Equal(t, testGroup.ID, getResponse.Group.ID)
}

func TestAPIGroupPermissionsGet_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/permissions"
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIGroupPermissionsPut tests the PUT /api/v1/admin/groups/{id}/permissions endpoint
func TestAPIGroupPermissionsPut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "put-test-group-resource", "PUT Test Group Resource")
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
	initialGroupPerm := createTestGroupPermission(t, testGroup.ID, perm1.ID)
	defer func() {
		_ = database.DeleteGroupPermission(context.Background(), nil, initialGroupPerm.ID)
	}()

	// Test: Update group permissions (replace with two different permissions)
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIDs:         []int64{perm2.ID, perm3.ID},
		ExpectedPermissionIDs: getGroupPermissionIDs(t, accessToken, testGroup.ID),
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.SuccessResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)
	assert.True(t, updateResponse.Success)

	// Verify permissions were updated correctly in database
	groupPerms, err := database.GetGroupPermissionsByGroupID(context.Background(), nil, testGroup.ID)
	require.NoError(t, err)
	assert.Len(t, groupPerms, 2)

	// Verify the correct permissions are assigned
	permIDs := make([]int64, len(groupPerms))
	for i, gp := range groupPerms {
		permIDs[i] = gp.PermissionID
	}
	assert.Contains(t, permIDs, perm2.ID)
	assert.Contains(t, permIDs, perm3.ID)
	assert.NotContains(t, permIDs, perm1.ID) // Original permission should be removed
}

func TestAPIGroupPermissionsPut_RemoveAllPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Setup: Create test resource and permission
	resource := createTestResource(t, "remove-test-group-resource", "Remove Test Group Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.ID)
	}()

	perm := createTestPermission(t, resource.ID, "test-perm", "Test permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm.ID)
	}()

	// Setup: Assign permission to group
	groupPerm := createTestGroupPermission(t, testGroup.ID, perm.ID)

	// Test: Remove all permissions (empty array)
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIDs:         []int64{},
		ExpectedPermissionIDs: getGroupPermissionIDs(t, accessToken, testGroup.ID),
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.SuccessResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)
	assert.True(t, updateResponse.Success)

	// Verify permission was removed
	groupPerms, err := database.GetGroupPermissionsByGroupID(context.Background(), nil, testGroup.ID)
	require.NoError(t, err)
	assert.Empty(t, groupPerms)

	// Verify the group permission record was actually deleted
	deletedGroupPerm, err := database.GetGroupPermissionByID(context.Background(), nil, groupPerm.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedGroupPerm)
}

func TestAPIGroupPermissionsPut_AddPermissionsToEmptyGroup(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group (with no initial permissions)
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "add-test-group-resource", "Add Test Group Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.ID)
	}()

	perm1 := createTestPermission(t, resource.ID, "admin", "Admin permission")
	perm2 := createTestPermission(t, resource.ID, "user", "User permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm1.ID)
		_ = database.DeletePermission(context.Background(), nil, perm2.ID)
	}()

	// Test: Add permissions to group that has none
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIDs:         []int64{perm1.ID, perm2.ID},
		ExpectedPermissionIDs: getGroupPermissionIDs(t, accessToken, testGroup.ID),
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.SuccessResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)
	assert.True(t, updateResponse.Success)

	// Verify permissions were added correctly
	groupPerms, err := database.GetGroupPermissionsByGroupID(context.Background(), nil, testGroup.ID)
	require.NoError(t, err)
	assert.Len(t, groupPerms, 2)

	// Cleanup: Delete created group permissions
	for _, gp := range groupPerms {
		_ = database.DeleteGroupPermission(context.Background(), nil, gp.ID)
	}

	// Verify the correct permissions are assigned
	permIDs := make([]int64, len(groupPerms))
	for i, gp := range groupPerms {
		permIDs[i] = gp.PermissionID
	}
	assert.Contains(t, permIDs, perm1.ID)
	assert.Contains(t, permIDs, perm2.ID)
}

func TestAPIGroupPermissionsPut_GroupNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update permissions for non-existent group
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIDs:         []int64{},
		ExpectedPermissionIDs: []int64{},
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/99999/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupPermissionsPut_PermissionNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Update with non-existent permission
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIDs:         []int64{99999},
		ExpectedPermissionIDs: getGroupPermissionIDs(t, accessToken, testGroup.ID),
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupPermissionsPut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Invalid JSON request body
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/permissions"
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

func TestAPIGroupPermissionsPut_InvalidGroupID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIDs:         []int64{},
		ExpectedPermissionIDs: []int64{},
	}

	testCases := []struct {
		name           string
		groupID        string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"negative ID", "-1", http.StatusNotFound},
		{"zero ID", "0", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + tc.groupID + "/permissions"
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupPermissionsPut_DuplicatePermissionIDs(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Setup: Create test resource and permission
	resource := createTestResource(t, "duplicate-test-resource", "Duplicate Test Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.ID)
	}()

	perm := createTestPermission(t, resource.ID, "test-perm", "Test permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm.ID)
	}()

	// Test: Update with duplicate permission IDs
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIDs:         []int64{perm.ID, perm.ID, perm.ID}, // Same permission multiple times
		ExpectedPermissionIDs: getGroupPermissionIDs(t, accessToken, testGroup.ID),
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be successful (duplicates handled gracefully)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify only one permission was assigned (no duplicates in database)
	groupPerms, err := database.GetGroupPermissionsByGroupID(context.Background(), nil, testGroup.ID)
	require.NoError(t, err)
	assert.Len(t, groupPerms, 1)
	assert.Equal(t, perm.ID, groupPerms[0].PermissionID)

	// Cleanup
	for _, gp := range groupPerms {
		_ = database.DeleteGroupPermission(context.Background(), nil, gp.ID)
	}
}

func TestAPIGroupPermissionsPut_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/permissions"
	req, err := http.NewRequest("PUT", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIGroupPermissionsPut_ComplexScenario(t *testing.T) {
	// This test covers a complex scenario with multiple operations:
	// 1. Group has permissions A, B, C
	// 2. Update to permissions B, C, D (remove A, add D, keep B and C)

	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "complex-test-resource", "Complex Test Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.ID)
	}()

	permA := createTestPermission(t, resource.ID, "permission-a", "Permission A")
	permB := createTestPermission(t, resource.ID, "permission-b", "Permission B")
	permC := createTestPermission(t, resource.ID, "permission-c", "Permission C")
	permD := createTestPermission(t, resource.ID, "permission-d", "Permission D")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, permA.ID)
		_ = database.DeletePermission(context.Background(), nil, permB.ID)
		_ = database.DeletePermission(context.Background(), nil, permC.ID)
		_ = database.DeletePermission(context.Background(), nil, permD.ID)
	}()

	// Setup: Initially assign permissions A, B, C
	groupPermA := createTestGroupPermission(t, testGroup.ID, permA.ID)
	groupPermB := createTestGroupPermission(t, testGroup.ID, permB.ID)
	groupPermC := createTestGroupPermission(t, testGroup.ID, permC.ID)
	defer func() {
		_ = database.DeleteGroupPermission(context.Background(), nil, groupPermA.ID)
		_ = database.DeleteGroupPermission(context.Background(), nil, groupPermB.ID)
		_ = database.DeleteGroupPermission(context.Background(), nil, groupPermC.ID)
	}()

	// Test: Update to permissions B, C, D (should remove A, keep B and C, add D)
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIDs:         []int64{permB.ID, permC.ID, permD.ID},
		ExpectedPermissionIDs: getGroupPermissionIDs(t, accessToken, testGroup.ID),
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify final permissions are correct
	groupPerms, err := database.GetGroupPermissionsByGroupID(context.Background(), nil, testGroup.ID)
	require.NoError(t, err)
	assert.Len(t, groupPerms, 3)

	// Cleanup: Delete any remaining group permissions
	for _, gp := range groupPerms {
		_ = database.DeleteGroupPermission(context.Background(), nil, gp.ID)
	}

	// Verify the correct permissions are assigned
	permIDs := make([]int64, len(groupPerms))
	for i, gp := range groupPerms {
		permIDs[i] = gp.PermissionID
	}
	assert.Contains(t, permIDs, permB.ID)    // Should be kept
	assert.Contains(t, permIDs, permC.ID)    // Should be kept
	assert.Contains(t, permIDs, permD.ID)    // Should be added
	assert.NotContains(t, permIDs, permA.ID) // Should be removed
}

// Helper function to create a test group permission
func createTestGroupPermission(t *testing.T, groupID, permissionID int64) *record.GroupPermission {
	groupPermission := &record.GroupPermission{
		GroupID:      groupID,
		PermissionID: permissionID,
	}
	err := database.CreateGroupPermission(context.Background(), nil, groupPermission)
	assert.NoError(t, err)
	return groupPermission
}

// getGroupPermissionIDs reads the group's grants through the API, as a caller does before a save,
// and returns their ids: the loaded set a save carries (#428).
func getGroupPermissionIDs(t *testing.T, accessToken string, groupID int64) []int64 {
	t.Helper()
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(groupID, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.GetGroupPermissionsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	ids := []int64{}
	for _, p := range body.Permissions {
		ids = append(ids, p.ID)
	}
	return ids
}

// The loaded set is required: absent or null answers 400 naming the field, and nothing is granted
// (#428).
func TestAPIGroupPermissionsPut_TheLoadedListIsRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	group := createTestGroup(t)
	t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, group.ID) })
	resource := createTestResource(t, "group-perm-expected-"+group.GroupIdentifier, "Group permission expected resource")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.ID) })
	perm := createTestPermission(t, resource.ID, "read", "Read permission")
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(group.ID, 10) + "/permissions"

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
			assert.Empty(t, getGroupPermissionIDs(t, accessToken, group.ID))
		})
	}
}

// Two administrators load the same grants; the first revokes one, and the second, still holding
// the set as it was, saves. The second is refused 409 CONCURRENT_UPDATE and writes nothing, rather
// than re-granting what the first had just revoked (#428).
func TestAPIGroupPermissionsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	group := createTestGroup(t)
	t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, group.ID) })
	resource := createTestResource(t, "group-perm-outdated-"+group.GroupIdentifier, "Group permission outdated resource")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.ID) })
	permA := createTestPermission(t, resource.ID, "read", "Read permission")
	permB := createTestPermission(t, resource.ID, "write", "Write permission")
	permC := createTestPermission(t, resource.ID, "delete", "Delete permission")
	createTestGroupPermission(t, group.ID, permA.ID)
	createTestGroupPermission(t, group.ID, permB.ID)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(group.ID, 10) + "/permissions"

	loadedByBoth := getGroupPermissionIDs(t, accessToken, group.ID)

	first := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateGroupPermissionsRequest{
		PermissionIDs: []int64{permB.ID}, ExpectedPermissionIDs: loadedByBoth})
	defer func() { _ = first.Body.Close() }()
	require.Equal(t, http.StatusOK, first.StatusCode)

	second := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateGroupPermissionsRequest{
		PermissionIDs: []int64{permA.ID, permB.ID, permC.ID}, ExpectedPermissionIDs: loadedByBoth})
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusConflict, second.StatusCode)
	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(second.Body).Decode(&body))
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
	assert.Contains(t, body["error_description"], "reload it")

	assert.Equal(t, []int64{permB.ID}, getGroupPermissionIDs(t, accessToken, group.ID), "the refused save wrote nothing")
}
