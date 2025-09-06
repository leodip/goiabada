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

// TestAPIUserGroupsPut tests the PUT /api/v1/admin/users/{id}/groups endpoint
func TestAPIUserGroupsPut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@groups-update.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test groups
	groups := make([]*models.Group, 3)
	for i := 0; i < 3; i++ {
		groups[i] = &models.Group{
			GroupIdentifier:  "update-group-" + strconv.Itoa(i+1),
			Description:      "Update Group " + strconv.Itoa(i+1),
			IncludeInIdToken: i%2 == 0, // alternate true/false
		}
		err = database.CreateGroup(nil, groups[i])
		assert.NoError(t, err)
		defer func(group *models.Group) {
			_ = database.DeleteGroup(nil, group.Id)
		}(groups[i])
	}

	// Setup: Initially assign user to group 0 and group 1
	for i := 0; i < 2; i++ {
		userGroup := &models.UserGroup{
			UserId:  testUser.Id,
			GroupId: groups[i].Id,
		}
		err = database.CreateUserGroup(nil, userGroup)
		assert.NoError(t, err)
		// Don't defer cleanup - the API call will modify these
	}

	// Test: Update user groups - remove group 0, keep group 1, add group 2
	updateReq := api.UpdateUserGroupsRequest{
		GroupIds: []int64{groups[1].Id, groups[2].Id},
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.GetUserGroupsResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: User should be in groups 1 and 2 only
	assert.Equal(t, testUser.Id, updateResponse.User.Id)
	assert.Len(t, updateResponse.Groups, 2)

	// Create map for easier verification
	responseGroupIds := make(map[int64]bool)
	for _, group := range updateResponse.Groups {
		responseGroupIds[group.Id] = true
	}

	assert.True(t, responseGroupIds[groups[1].Id], "Should include group 1")
	assert.True(t, responseGroupIds[groups[2].Id], "Should include group 2")
	assert.False(t, responseGroupIds[groups[0].Id], "Should not include group 0")

	// Verify changes were persisted to database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	err = database.UserLoadGroups(nil, updatedUser)
	assert.NoError(t, err)

	assert.Len(t, updatedUser.Groups, 2)
	dbGroupIds := make(map[int64]bool)
	for _, group := range updatedUser.Groups {
		dbGroupIds[group.Id] = true
	}

	assert.True(t, dbGroupIds[groups[1].Id], "Database should include group 1")
	assert.True(t, dbGroupIds[groups[2].Id], "Database should include group 2")
	assert.False(t, dbGroupIds[groups[0].Id], "Database should not include group 0")
}

func TestAPIUserGroupsPut_EmptyGroups(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@empty-groups.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test group and assign user to it
	testGroup := &models.Group{
		GroupIdentifier: "remove-all-group",
		Description:     "Group to be removed",
	}
	err = database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	userGroup := &models.UserGroup{
		UserId:  testUser.Id,
		GroupId: testGroup.Id,
	}
	err = database.CreateUserGroup(nil, userGroup)
	assert.NoError(t, err)

	// Test: Remove all groups (empty array)
	updateReq := api.UpdateUserGroupsRequest{
		GroupIds: []int64{}, // Empty array
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.GetUserGroupsResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: User should have no groups
	assert.Equal(t, testUser.Id, updateResponse.User.Id)
	assert.Len(t, updateResponse.Groups, 0)

	// Verify in database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	err = database.UserLoadGroups(nil, updatedUser)
	assert.NoError(t, err)
	assert.Len(t, updatedUser.Groups, 0)
}

func TestAPIUserGroupsPut_NonExistentGroup(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@invalid-group.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Try to assign user to non-existent group
	updateReq := api.UpdateUserGroupsRequest{
		GroupIds: []int64{99999}, // Non-existent group ID
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return 400 due to validation error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserGroupsPut_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update groups for non-existent user
	updateReq := api.UpdateUserGroupsRequest{
		GroupIds: []int64{}, // Empty groups
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/groups"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserGroupsPut_InvalidId(t *testing.T) {
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

	updateReq := api.UpdateUserGroupsRequest{
		GroupIds: []int64{},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.userId + "/groups"
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserGroupsPut_InvalidRequestBody(t *testing.T) {
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
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	req, err := http.NewRequest("PUT", url, nil) // No body
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserGroupsPut_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth-update.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}