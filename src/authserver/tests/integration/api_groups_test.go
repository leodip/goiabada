package integrationtests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIGroupsGet tests the GET /api/v1/admin/groups endpoint
func TestAPIGroupsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test groups
	testGroup1 := &models.Group{
		GroupIdentifier:      "test-group-1",
		Description:          "Test Group 1",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}
	err := database.CreateGroup(nil, testGroup1)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup1.Id)
	}()

	testGroup2 := &models.Group{
		GroupIdentifier:      "test-group-2",
		Description:          "Test Group 2",
		IncludeInIdToken:     false,
		IncludeInAccessToken: true,
	}
	err = database.CreateGroup(nil, testGroup2)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup2.Id)
	}()

	// Test: Get all groups
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetGroupsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should include our test groups (may include others from database)
	assert.GreaterOrEqual(t, len(getResponse.Groups), 2)

	// Find our test groups in the response
	var foundGroup1, foundGroup2 *api.GroupResponse
	for i := range getResponse.Groups {
		if getResponse.Groups[i].GroupIdentifier == "test-group-1" {
			foundGroup1 = &getResponse.Groups[i]
		}
		if getResponse.Groups[i].GroupIdentifier == "test-group-2" {
			foundGroup2 = &getResponse.Groups[i]
		}
	}

	// Assert: Both test groups should be found
	assert.NotNil(t, foundGroup1)
	assert.Equal(t, testGroup1.Id, foundGroup1.Id)
	assert.Equal(t, "Test Group 1", foundGroup1.Description)
	assert.True(t, foundGroup1.IncludeInIdToken)
	assert.False(t, foundGroup1.IncludeInAccessToken)
	assert.NotNil(t, foundGroup1.CreatedAt, "CreatedAt should be populated")
	assert.NotNil(t, foundGroup1.UpdatedAt, "UpdatedAt should be populated")

	assert.NotNil(t, foundGroup2)
	assert.Equal(t, testGroup2.Id, foundGroup2.Id)
	assert.Equal(t, "Test Group 2", foundGroup2.Description)
	assert.False(t, foundGroup2.IncludeInIdToken)
	assert.True(t, foundGroup2.IncludeInAccessToken)
	assert.NotNil(t, foundGroup2.CreatedAt, "CreatedAt should be populated")
	assert.NotNil(t, foundGroup2.UpdatedAt, "UpdatedAt should be populated")
}

func TestAPIGroupsGet_EmptyGroups(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Note: In a real environment there might be default groups,
	// but this test verifies the endpoint works even with minimal data

	// Test: Get all groups
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetGroupsResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return a valid groups array (empty or with existing groups)
	assert.NotNil(t, getResponse.Groups)
}

func TestAPIGroupsGet_Unauthorized(t *testing.T) {
	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIGroupsGet_InvalidToken(t *testing.T) {
	// Test: Request with invalid access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIGroupsGet_EnhancedResponseStructure(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group with all enhanced fields
	testGroup := &models.Group{
		GroupIdentifier:      "enhanced-test-group",
		Description:          "Enhanced Test Group",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Get all groups
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetGroupsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Find our test group
	var foundGroup *api.GroupResponse
	for i := range getResponse.Groups {
		if getResponse.Groups[i].GroupIdentifier == "enhanced-test-group" {
			foundGroup = &getResponse.Groups[i]
			break
		}
	}

	// Assert: Test group should be found
	assert.NotNil(t, foundGroup, "Enhanced test group should be found")

	// Assert: All enhanced fields should be present and properly typed
	assert.Greater(t, foundGroup.Id, int64(0), "Id should be a positive integer")
	assert.Equal(t, "enhanced-test-group", foundGroup.GroupIdentifier)
	assert.Equal(t, "Enhanced Test Group", foundGroup.Description)
	assert.True(t, foundGroup.IncludeInIdToken, "IncludeInIdToken should be true")
	assert.True(t, foundGroup.IncludeInAccessToken, "IncludeInAccessToken should be true")

	// Assert: Timestamp fields should be present and valid
	assert.NotNil(t, foundGroup.CreatedAt, "CreatedAt should not be nil")
	assert.NotNil(t, foundGroup.UpdatedAt, "UpdatedAt should not be nil")
	assert.False(t, foundGroup.CreatedAt.IsZero(), "CreatedAt should not be zero time")
	assert.False(t, foundGroup.UpdatedAt.IsZero(), "UpdatedAt should not be zero time")

	// Assert: CreatedAt and UpdatedAt should be reasonable (within the last minute)
	// Note: We're being lenient here since test execution timing can vary
	timeCutoff := time.Now().Add(-1 * time.Minute)
	assert.True(t, foundGroup.CreatedAt.After(timeCutoff), "CreatedAt should be recent")
	assert.True(t, foundGroup.UpdatedAt.After(timeCutoff), "UpdatedAt should be recent")

	// Assert: CreatedAt should be before or equal to UpdatedAt
	assert.True(t, foundGroup.CreatedAt.Before(*foundGroup.UpdatedAt) || foundGroup.CreatedAt.Equal(*foundGroup.UpdatedAt),
		"CreatedAt should be before or equal to UpdatedAt")
}

func TestAPIGroupsGet_MixedTokenInclusion(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test groups with different token inclusion settings
	testCases := []struct {
		identifier           string
		includeInIdToken     bool
		includeInAccessToken bool
	}{
		{"mixed-group-1", true, false},  // Only ID token
		{"mixed-group-2", false, true},  // Only access token
		{"mixed-group-3", true, true},   // Both tokens
		{"mixed-group-4", false, false}, // Neither token
	}

	var createdGroups []*models.Group
	for _, tc := range testCases {
		group := &models.Group{
			GroupIdentifier:      tc.identifier,
			Description:          "Test Group for " + tc.identifier,
			IncludeInIdToken:     tc.includeInIdToken,
			IncludeInAccessToken: tc.includeInAccessToken,
		}
		err := database.CreateGroup(nil, group)
		assert.NoError(t, err)
		createdGroups = append(createdGroups, group)
	}

	defer func() {
		// Cleanup: Delete all created groups
		for _, group := range createdGroups {
			_ = database.DeleteGroup(nil, group.Id)
		}
	}()

	// Test: Get all groups
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetGroupsResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Verify each test group has correct token inclusion settings
	groupMap := make(map[string]api.GroupResponse)
	for _, group := range getResponse.Groups {
		groupMap[group.GroupIdentifier] = group
	}

	for _, tc := range testCases {
		foundGroup, exists := groupMap[tc.identifier]
		assert.True(t, exists, "Group %s should be found", tc.identifier)
		assert.Equal(t, tc.includeInIdToken, foundGroup.IncludeInIdToken,
			"Group %s IncludeInIdToken should be %v", tc.identifier, tc.includeInIdToken)
		assert.Equal(t, tc.includeInAccessToken, foundGroup.IncludeInAccessToken,
			"Group %s IncludeInAccessToken should be %v", tc.identifier, tc.includeInAccessToken)
	}
}

// TestAPIUserGroupsGet tests the GET /api/v1/admin/users/{id}/groups endpoint
func TestAPIUserGroupsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@user-groups.test",
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
	testGroup1 := &models.Group{
		GroupIdentifier:  "user-group-1",
		Description:      "User Group 1",
		IncludeInIdToken: true,
	}
	err = database.CreateGroup(nil, testGroup1)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup1.Id)
	}()

	testGroup2 := &models.Group{
		GroupIdentifier:  "user-group-2",
		Description:      "User Group 2",
		IncludeInIdToken: false,
	}
	err = database.CreateGroup(nil, testGroup2)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup2.Id)
	}()

	// Setup: Assign user to group1 only
	userGroup := &models.UserGroup{
		UserId:  testUser.Id,
		GroupId: testGroup1.Id,
	}
	err = database.CreateUserGroup(nil, userGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUserGroup(nil, userGroup.Id)
	}()

	// Test: Get user groups
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetUserGroupsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: User data should be correct
	assert.Equal(t, testUser.Id, getResponse.User.Id)
	assert.Equal(t, testUser.Email, getResponse.User.Email)
	assert.Equal(t, testUser.GivenName, getResponse.User.GivenName)

	// Assert: Should return only group1
	assert.Len(t, getResponse.Groups, 1)
	assert.Equal(t, testGroup1.Id, getResponse.Groups[0].Id)
	assert.Equal(t, "user-group-1", getResponse.Groups[0].GroupIdentifier)
	assert.Equal(t, "User Group 1", getResponse.Groups[0].Description)
	assert.True(t, getResponse.Groups[0].IncludeInIdToken)
}

func TestAPIUserGroupsGet_NoGroups(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without groups
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@no-groups.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Get user groups for user with no groups
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/groups"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetUserGroupsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return user with empty groups array
	assert.Equal(t, testUser.Id, getResponse.User.Id)
	assert.Len(t, getResponse.Groups, 0)
}

func TestAPIUserGroupsGet_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get groups for non-existent user
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/groups"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserGroupsGet_InvalidId(t *testing.T) {
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
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.userId + "/groups"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserGroupsGet_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth-groups.test",
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
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

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

func TestHandleAPIGroupCreatePost_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Create request data
	reqData := map[string]interface{}{
		"groupIdentifier":      "test-group-" + gofakeit.LetterN(6),
		"description":          "Test Group Description",
		"includeInIdToken":     true,
		"includeInAccessToken": false,
	}

	// Make POST request
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqData)
	defer resp.Body.Close()

	// Assert response
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	// Verify response structure
	assert.Contains(t, response, "group")
	group := response["group"].(map[string]interface{})
	assert.Equal(t, reqData["groupIdentifier"], group["groupIdentifier"])
	assert.Equal(t, reqData["description"], group["description"])
	assert.Equal(t, reqData["includeInIdToken"], group["includeInIdToken"])
	assert.Equal(t, reqData["includeInAccessToken"], group["includeInAccessToken"])
	assert.NotZero(t, group["id"])

	// Clean up - delete the created group
	groupId := int64(group["id"].(float64))
	defer func() {
		_ = database.DeleteGroup(nil, groupId)
	}()
}

func TestHandleAPIGroupCreatePost_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"

	testCases := []struct {
		name           string
		requestData    map[string]interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Empty group identifier",
			requestData: map[string]interface{}{
				"groupIdentifier":      "",
				"description":          "Test Description",
				"includeInIdToken":     true,
				"includeInAccessToken": false,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Group identifier is required",
		},
		{
			name: "Group identifier too short",
			requestData: map[string]interface{}{
				"groupIdentifier":      "ab",
				"description":          "Test Description",
				"includeInIdToken":     true,
				"includeInAccessToken": false,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "must be at least 3 characters long",
		},
		{
			name: "Group identifier too long",
			requestData: map[string]interface{}{
				"groupIdentifier":      strings.Repeat("a", 39),
				"description":          "Test Description",
				"includeInIdToken":     true,
				"includeInAccessToken": false,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "cannot exceed a maximum length of 38 characters",
		},
		{
			name: "Invalid group identifier characters",
			requestData: map[string]interface{}{
				"groupIdentifier":      "invalid@group!",
				"description":          "Test Description",
				"includeInIdToken":     true,
				"includeInAccessToken": false,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid identifier format",
		},
		{
			name: "Description too long",
			requestData: map[string]interface{}{
				"groupIdentifier":      "valid-group",
				"description":          strings.Repeat("a", 101),
				"includeInIdToken":     true,
				"includeInAccessToken": false,
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "cannot exceed a maximum length of 100 characters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := makeAPIRequest(t, "POST", url, accessToken, tc.requestData)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			var response map[string]interface{}
			err := json.NewDecoder(resp.Body).Decode(&response)
			assert.NoError(t, err)
			assert.Contains(t, response["error"].(map[string]interface{})["message"].(string), tc.expectedError)
		})
	}
}

func TestHandleAPIGroupCreatePost_DuplicateGroupIdentifier(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Create a group first
	existingGroup := &models.Group{
		GroupIdentifier:      "existing-group-" + gofakeit.LetterN(6),
		Description:          "Existing Group",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}
	err := database.CreateGroup(nil, existingGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, existingGroup.Id)
	}()

	// Try to create another group with same identifier
	reqData := map[string]interface{}{
		"groupIdentifier":      existingGroup.GroupIdentifier,
		"description":          "Duplicate Group",
		"includeInIdToken":     false,
		"includeInAccessToken": true,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqData)
	defer resp.Body.Close()

	// Assert response
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"].(map[string]interface{})["message"].(string), "The group identifier is already in use")
}

func TestHandleAPIGroupCreatePost_InputSanitization(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Create request data with potentially malicious input in description
	reqData := map[string]interface{}{
		"groupIdentifier":      "test-group-" + gofakeit.LetterN(6), // Valid identifier (no spaces) to pass validation
		"description":          "  <script>alert('xss')</script>Test Description  ",
		"includeInIdToken":     true,
		"includeInAccessToken": false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqData)
	defer resp.Body.Close()

	// Assert response
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	group := response["group"].(map[string]interface{})

	// Verify input was sanitized
	assert.Equal(t, reqData["groupIdentifier"].(string), group["groupIdentifier"])
	// Description should be sanitized (script tags removed) and trimmed
	expectedDesc := "Test Description"
	assert.Equal(t, expectedDesc, group["description"])

	// Clean up
	groupId := int64(group["id"].(float64))
	defer func() {
		_ = database.DeleteGroup(nil, groupId)
	}()
}

func TestHandleAPIGroupCreatePost_Unauthorized(t *testing.T) {
	reqData := map[string]interface{}{
		"groupIdentifier":      "test-group",
		"description":          "Test Description",
		"includeInIdToken":     true,
		"includeInAccessToken": false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "POST", url, "", reqData) // Empty access token
	defer resp.Body.Close()

	// Assert response
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandleAPIGroupCreatePost_InvalidJSON(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Invalid JSON body
	invalidJSON := `{"groupIdentifier": "test", "description": }`

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	req, err := http.NewRequest("POST", url, strings.NewReader(invalidJSON))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert response
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"].(map[string]interface{})["message"].(string), "Invalid")
}

func TestHandleAPIGroupCreatePost_MissingContentType(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	reqData := map[string]interface{}{
		"groupIdentifier":      "test-group",
		"description":          "Test Description",
		"includeInIdToken":     true,
		"includeInAccessToken": false,
	}

	jsonBody, err := json.Marshal(reqData)
	assert.NoError(t, err)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	assert.NoError(t, err)
	// Missing Content-Type header
	req.Header.Set("Authorization", "Bearer "+accessToken)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert response - should still work or return appropriate error
	// The exact behavior depends on implementation
	assert.True(t, resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusCreated)
}
