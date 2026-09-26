package integrationtests

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/models"
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
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "test-group-resource", "Test Group Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	perm1 := createTestPermission(t, resource.Id, "read", "Read permission")
	perm2 := createTestPermission(t, resource.Id, "write", "Write permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm1.Id)
		_ = database.DeletePermission(context.Background(), nil, perm2.Id)
	}()

	// Setup: Assign permissions to group
	groupPerm1 := createTestGroupPermission(t, testGroup.Id, perm1.Id)
	groupPerm2 := createTestGroupPermission(t, testGroup.Id, perm2.Id)
	defer func() {
		_ = database.DeleteGroupPermission(context.Background(), nil, groupPerm1.Id)
		_ = database.DeleteGroupPermission(context.Background(), nil, groupPerm2.Id)
	}()

	// Test: Get group permissions
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetGroupPermissionsResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Group information
	assert.Equal(t, testGroup.Id, getResponse.Group.Id)
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
	assert.Equal(t, resource.Id, readPerm.ResourceId)
	assert.Equal(t, "test-group-resource", readPerm.Resource.ResourceIdentifier)
	assert.Equal(t, "Test Group Resource", readPerm.Resource.Description)

	writePerm, exists := permMap["write"]
	assert.True(t, exists)
	assert.Equal(t, "Write permission", writePerm.Description)
	assert.Equal(t, resource.Id, writePerm.ResourceId)
	assert.Equal(t, "test-group-resource", writePerm.Resource.ResourceIdentifier)
}

func TestAPIGroupPermissionsGet_GroupNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get permissions for non-existent group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/99999/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupPermissionsGet_InvalidGroupId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get permissions with invalid group ID
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/invalid/permissions"
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
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	// Test: Get group permissions for group with no permissions
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetGroupPermissionsResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return empty permissions array
	assert.Len(t, getResponse.Permissions, 0)
	assert.Equal(t, testGroup.Id, getResponse.Group.Id)
}

func TestAPIGroupPermissionsGet_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/permissions"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
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
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "put-test-group-resource", "PUT Test Group Resource")
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
	initialGroupPerm := createTestGroupPermission(t, testGroup.Id, perm1.Id)
	defer func() {
		_ = database.DeleteGroupPermission(context.Background(), nil, initialGroupPerm.Id)
	}()

	// Test: Update group permissions (replace with two different permissions)
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIds:         []int64{perm2.Id, perm3.Id},
		ExpectedPermissionIds: getGroupPermissionIds(t, accessToken, testGroup.Id),
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.SuccessResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)
	assert.True(t, updateResponse.Success)

	// Verify permissions were updated correctly in database
	groupPerms, err := database.GetGroupPermissionsByGroupId(context.Background(), nil, testGroup.Id)
	assert.NoError(t, err)
	assert.Len(t, groupPerms, 2)

	// Verify the correct permissions are assigned
	permIds := make([]int64, len(groupPerms))
	for i, gp := range groupPerms {
		permIds[i] = gp.PermissionId
	}
	assert.Contains(t, permIds, perm2.Id)
	assert.Contains(t, permIds, perm3.Id)
	assert.NotContains(t, permIds, perm1.Id) // Original permission should be removed
}

func TestAPIGroupPermissionsPut_RemoveAllPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	// Setup: Create test resource and permission
	resource := createTestResource(t, "remove-test-group-resource", "Remove Test Group Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	perm := createTestPermission(t, resource.Id, "test-perm", "Test permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm.Id)
	}()

	// Setup: Assign permission to group
	groupPerm := createTestGroupPermission(t, testGroup.Id, perm.Id)

	// Test: Remove all permissions (empty array)
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIds:         []int64{},
		ExpectedPermissionIds: getGroupPermissionIds(t, accessToken, testGroup.Id),
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.SuccessResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)
	assert.True(t, updateResponse.Success)

	// Verify permission was removed
	groupPerms, err := database.GetGroupPermissionsByGroupId(context.Background(), nil, testGroup.Id)
	assert.NoError(t, err)
	assert.Len(t, groupPerms, 0)

	// Verify the group permission record was actually deleted
	deletedGroupPerm, err := database.GetGroupPermissionById(context.Background(), nil, groupPerm.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedGroupPerm)
}

func TestAPIGroupPermissionsPut_AddPermissionsToEmptyGroup(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group (with no initial permissions)
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "add-test-group-resource", "Add Test Group Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	perm1 := createTestPermission(t, resource.Id, "admin", "Admin permission")
	perm2 := createTestPermission(t, resource.Id, "user", "User permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm1.Id)
		_ = database.DeletePermission(context.Background(), nil, perm2.Id)
	}()

	// Test: Add permissions to group that has none
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIds:         []int64{perm1.Id, perm2.Id},
		ExpectedPermissionIds: getGroupPermissionIds(t, accessToken, testGroup.Id),
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.SuccessResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)
	assert.True(t, updateResponse.Success)

	// Verify permissions were added correctly
	groupPerms, err := database.GetGroupPermissionsByGroupId(context.Background(), nil, testGroup.Id)
	assert.NoError(t, err)
	assert.Len(t, groupPerms, 2)

	// Cleanup: Delete created group permissions
	for _, gp := range groupPerms {
		_ = database.DeleteGroupPermission(context.Background(), nil, gp.Id)
	}

	// Verify the correct permissions are assigned
	permIds := make([]int64, len(groupPerms))
	for i, gp := range groupPerms {
		permIds[i] = gp.PermissionId
	}
	assert.Contains(t, permIds, perm1.Id)
	assert.Contains(t, permIds, perm2.Id)
}

func TestAPIGroupPermissionsPut_GroupNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update permissions for non-existent group
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIds:         []int64{},
		ExpectedPermissionIds: []int64{},
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/99999/permissions"
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
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	// Test: Update with non-existent permission
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIds:         []int64{99999},
		ExpectedPermissionIds: getGroupPermissionIds(t, accessToken, testGroup.Id),
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/permissions"
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
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	// Test: Invalid JSON request body
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/permissions"
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

func TestAPIGroupPermissionsPut_InvalidGroupId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIds:         []int64{},
		ExpectedPermissionIds: []int64{},
	}

	testCases := []struct {
		name           string
		groupId        string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"negative ID", "-1", http.StatusNotFound},
		{"zero ID", "0", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + tc.groupId + "/permissions"
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupPermissionsPut_DuplicatePermissionIds(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	// Setup: Create test resource and permission
	resource := createTestResource(t, "duplicate-test-resource", "Duplicate Test Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	perm := createTestPermission(t, resource.Id, "test-perm", "Test permission")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, perm.Id)
	}()

	// Test: Update with duplicate permission IDs
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIds:         []int64{perm.Id, perm.Id, perm.Id}, // Same permission multiple times
		ExpectedPermissionIds: getGroupPermissionIds(t, accessToken, testGroup.Id),
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be successful (duplicates handled gracefully)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify only one permission was assigned (no duplicates in database)
	groupPerms, err := database.GetGroupPermissionsByGroupId(context.Background(), nil, testGroup.Id)
	assert.NoError(t, err)
	assert.Len(t, groupPerms, 1)
	assert.Equal(t, perm.Id, groupPerms[0].PermissionId)

	// Cleanup
	for _, gp := range groupPerms {
		_ = database.DeleteGroupPermission(context.Background(), nil, gp.Id)
	}
}

func TestAPIGroupPermissionsPut_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/permissions"
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
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
		_ = database.DeleteGroup(context.Background(), nil, testGroup.Id)
	}()

	// Setup: Create test resource and permissions
	resource := createTestResource(t, "complex-test-resource", "Complex Test Resource")
	defer func() {
		_ = database.DeleteResource(context.Background(), nil, resource.Id)
	}()

	permA := createTestPermission(t, resource.Id, "permission-a", "Permission A")
	permB := createTestPermission(t, resource.Id, "permission-b", "Permission B")
	permC := createTestPermission(t, resource.Id, "permission-c", "Permission C")
	permD := createTestPermission(t, resource.Id, "permission-d", "Permission D")
	defer func() {
		_ = database.DeletePermission(context.Background(), nil, permA.Id)
		_ = database.DeletePermission(context.Background(), nil, permB.Id)
		_ = database.DeletePermission(context.Background(), nil, permC.Id)
		_ = database.DeletePermission(context.Background(), nil, permD.Id)
	}()

	// Setup: Initially assign permissions A, B, C
	groupPermA := createTestGroupPermission(t, testGroup.Id, permA.Id)
	groupPermB := createTestGroupPermission(t, testGroup.Id, permB.Id)
	groupPermC := createTestGroupPermission(t, testGroup.Id, permC.Id)
	defer func() {
		_ = database.DeleteGroupPermission(context.Background(), nil, groupPermA.Id)
		_ = database.DeleteGroupPermission(context.Background(), nil, groupPermB.Id)
		_ = database.DeleteGroupPermission(context.Background(), nil, groupPermC.Id)
	}()

	// Test: Update to permissions B, C, D (should remove A, keep B and C, add D)
	updateReq := api.UpdateGroupPermissionsRequest{
		PermissionIds:         []int64{permB.Id, permC.Id, permD.Id},
		ExpectedPermissionIds: getGroupPermissionIds(t, accessToken, testGroup.Id),
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify final permissions are correct
	groupPerms, err := database.GetGroupPermissionsByGroupId(context.Background(), nil, testGroup.Id)
	assert.NoError(t, err)
	assert.Len(t, groupPerms, 3)

	// Cleanup: Delete any remaining group permissions
	for _, gp := range groupPerms {
		_ = database.DeleteGroupPermission(context.Background(), nil, gp.Id)
	}

	// Verify the correct permissions are assigned
	permIds := make([]int64, len(groupPerms))
	for i, gp := range groupPerms {
		permIds[i] = gp.PermissionId
	}
	assert.Contains(t, permIds, permB.Id)    // Should be kept
	assert.Contains(t, permIds, permC.Id)    // Should be kept
	assert.Contains(t, permIds, permD.Id)    // Should be added
	assert.NotContains(t, permIds, permA.Id) // Should be removed
}

// Helper function to create a test group permission
func createTestGroupPermission(t *testing.T, groupId, permissionId int64) *models.GroupPermission {
	groupPermission := &models.GroupPermission{
		GroupId:      groupId,
		PermissionId: permissionId,
	}
	err := database.CreateGroupPermission(context.Background(), nil, groupPermission)
	assert.NoError(t, err)
	return groupPermission
}

// getGroupPermissionIds reads the group's grants through the API, as a caller does before a save,
// and returns their ids: the loaded set a save carries (#428).
func getGroupPermissionIds(t *testing.T, accessToken string, groupId int64) []int64 {
	t.Helper()
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(groupId, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.GetGroupPermissionsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	ids := []int64{}
	for _, p := range body.Permissions {
		ids = append(ids, p.Id)
	}
	return ids
}

// The loaded set is required: absent or null answers 400 naming the field, and nothing is granted
// (#428).
func TestAPIGroupPermissionsPut_TheLoadedListIsRequired(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	group := createTestGroup(t)
	t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, group.Id) })
	resource := createTestResource(t, "group-perm-expected-"+group.GroupIdentifier, "Group permission expected resource")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) })
	perm := createTestPermission(t, resource.Id, "read", "Read permission")
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(group.Id, 10) + "/permissions"

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
			assert.Empty(t, getGroupPermissionIds(t, accessToken, group.Id))
		})
	}
}

// Two administrators load the same grants; the first revokes one, and the second, still holding
// the set as it was, saves. The second is refused 409 CONCURRENT_UPDATE and writes nothing, rather
// than re-granting what the first had just revoked (#428).
func TestAPIGroupPermissionsPut_AnOutdatedLoadedListIsRefused(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	group := createTestGroup(t)
	t.Cleanup(func() { _ = database.DeleteGroup(context.Background(), nil, group.Id) })
	resource := createTestResource(t, "group-perm-outdated-"+group.GroupIdentifier, "Group permission outdated resource")
	t.Cleanup(func() { _ = database.DeleteResource(context.Background(), nil, resource.Id) })
	permA := createTestPermission(t, resource.Id, "read", "Read permission")
	permB := createTestPermission(t, resource.Id, "write", "Write permission")
	permC := createTestPermission(t, resource.Id, "delete", "Delete permission")
	createTestGroupPermission(t, group.Id, permA.Id)
	createTestGroupPermission(t, group.Id, permB.Id)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(group.Id, 10) + "/permissions"

	loadedByBoth := getGroupPermissionIds(t, accessToken, group.Id)

	first := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateGroupPermissionsRequest{
		PermissionIds: []int64{permB.Id}, ExpectedPermissionIds: loadedByBoth})
	defer func() { _ = first.Body.Close() }()
	require.Equal(t, http.StatusOK, first.StatusCode)

	second := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateGroupPermissionsRequest{
		PermissionIds: []int64{permA.Id, permB.Id, permC.Id}, ExpectedPermissionIds: loadedByBoth})
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, http.StatusConflict, second.StatusCode)
	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(second.Body).Decode(&body))
	assert.Equal(t, "CONCURRENT_UPDATE", body["error_code"])
	assert.Contains(t, body["error_description"], "reload it")

	assert.Equal(t, []int64{permB.Id}, getGroupPermissionIds(t, accessToken, group.Id), "the refused save wrote nothing")
}
