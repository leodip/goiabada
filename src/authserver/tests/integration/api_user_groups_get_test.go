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