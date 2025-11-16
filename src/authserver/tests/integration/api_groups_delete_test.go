package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIGroupDelete tests the DELETE /api/v1/admin/groups/{id} endpoint
func TestAPIGroupDelete_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	// Note: We won't defer deletion since we're testing the delete endpoint

	// Test: Delete group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify group was actually deleted from database
	deletedGroup, err := database.GetGroupById(nil, testGroup.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedGroup, "Group should be deleted from database")
}

func TestAPIGroupDelete_SuccessWithMembers(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	// Note: We won't defer deletion since we're testing the delete endpoint

	// Setup: Create test user and add to group
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@groupdelete.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	userGroup := &models.UserGroup{
		UserId:  testUser.Id,
		GroupId: testGroup.Id,
	}
	err = database.CreateUserGroup(nil, userGroup)
	assert.NoError(t, err)
	// Note: UserGroup should be automatically deleted when group is deleted

	// Test: Delete group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify group was actually deleted from database
	deletedGroup, err := database.GetGroupById(nil, testGroup.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedGroup, "Group should be deleted from database")

	// Verify user-group relationship was also deleted
	userGroups, err := database.GetUserGroupsByUserId(nil, testUser.Id)
	assert.NoError(t, err)
	// Should not contain our deleted group
	for _, ug := range userGroups {
		assert.NotEqual(t, testGroup.Id, ug.GroupId, "UserGroup relationship should be deleted")
	}
}

func TestAPIGroupDelete_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Delete non-existent group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/99999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupDelete_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		groupId        string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusMethodNotAllowed}, // DELETE without ID hits different route
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + tc.groupId
			resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupDelete_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	req, err := http.NewRequest("DELETE", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify group still exists (not deleted)
	existingGroup, err := database.GetGroupById(nil, testGroup.Id)
	assert.NoError(t, err)
	assert.NotNil(t, existingGroup, "Group should still exist after unauthorized delete attempt")
}

func TestAPIGroupDelete_InvalidToken(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Request with invalid access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, "invalid-token", nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify group still exists (not deleted)
	existingGroup, err := database.GetGroupById(nil, testGroup.Id)
	assert.NoError(t, err)
	assert.NotNil(t, existingGroup, "Group should still exist after invalid token delete attempt")
}

func TestAPIGroupDelete_WithGroupPermissions(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	// Note: We won't defer deletion since we're testing the delete endpoint

	// Setup: Create test permission and group-permission relationship
	testPermission := &models.Permission{
		PermissionIdentifier: "test-permission-for-group-delete",
		Description:          "Test permission for group deletion",
		ResourceId:           1, // Assuming resource with ID 1 exists
	}
	err := database.CreatePermission(nil, testPermission)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeletePermission(nil, testPermission.Id)
	}()

	groupPermission := &models.GroupPermission{
		GroupId:      testGroup.Id,
		PermissionId: testPermission.Id,
	}
	err = database.CreateGroupPermission(nil, groupPermission)
	assert.NoError(t, err)
	// Note: GroupPermission should be automatically deleted when group is deleted

	// Test: Delete group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify group was actually deleted from database
	deletedGroup, err := database.GetGroupById(nil, testGroup.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedGroup, "Group should be deleted from database")

	// Verify group-permission relationship was also deleted
	groupPermissions, err := database.GetGroupPermissionsByGroupId(nil, testGroup.Id)
	assert.NoError(t, err)
	assert.Empty(t, groupPermissions, "GroupPermission relationships should be deleted")
}

func TestAPIGroupDelete_ResponseStructure(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	// Note: We won't defer deletion since we're testing the delete endpoint

	// Test: Delete group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful with proper content type
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response - should be empty JSON object or success message
	var deleteResponse map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&deleteResponse)
	assert.NoError(t, err)
}
