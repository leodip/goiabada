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

// TestAPIUserGroupsGet tests the GET /api/v1/admin/users/{id}/groups endpoint
func TestAPIUserGroupsGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@user-groups.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test groups
	testGroup1 := &record.Group{
		GroupIdentifier:  "user-group-1",
		Description:      "User Group 1",
		IncludeInIDToken: true,
	}
	err = database.CreateGroup(context.Background(), nil, testGroup1)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup1.ID)
	}()

	testGroup2 := &record.Group{
		GroupIdentifier:  "user-group-2",
		Description:      "User Group 2",
		IncludeInIDToken: false,
	}
	err = database.CreateGroup(context.Background(), nil, testGroup2)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup2.ID)
	}()

	// Setup: Assign user to group1 only
	userGroup := &record.UserGroup{
		UserID:  testUser.ID,
		GroupID: testGroup1.ID,
	}
	err = database.CreateUserGroup(context.Background(), nil, userGroup)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUserGroup(context.Background(), nil, userGroup.ID)
	}()

	// Test: Get user groups
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/groups"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetUserGroupsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: User data should be correct
	assert.Equal(t, testUser.ID, getResponse.User.ID)
	assert.Equal(t, testUser.Email, getResponse.User.Email)
	assert.Equal(t, testUser.GivenName, getResponse.User.GivenName)

	// Assert: Should return only group1
	assert.Len(t, getResponse.Groups, 1)
	assert.Equal(t, testGroup1.ID, getResponse.Groups[0].ID)
	assert.Equal(t, "user-group-1", getResponse.Groups[0].GroupIdentifier)
	assert.Equal(t, "User Group 1", getResponse.Groups[0].Description)
	assert.True(t, getResponse.Groups[0].IncludeInIDToken)
}

func TestAPIUserGroupsGet_NoGroups(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without groups
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@no-groups.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Get user groups for user with no groups
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/groups"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetUserGroupsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: Should return user with empty groups array
	assert.Equal(t, testUser.ID, getResponse.User.ID)
	assert.Empty(t, getResponse.Groups)
}

func TestAPIUserGroupsGet_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get groups for non-existent user
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/99999/groups"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserGroupsGet_InvalidID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		userID         string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		// An empty segment matches no route, so the group answers 404 (#462 decision 4).
		{"empty ID", "", http.StatusNotFound},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + tc.userID + "/groups"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserGroupsGet_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@unauth-groups.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/groups"
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
