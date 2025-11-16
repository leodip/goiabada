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

// TestAPIGroupGet tests the GET /api/v1/admin/groups/{id} endpoint
func TestAPIGroupGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Get group by ID
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetGroupResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Group data should match
	assert.Equal(t, testGroup.Id, getResponse.Group.Id)
	assert.Equal(t, testGroup.GroupIdentifier, getResponse.Group.GroupIdentifier)
	assert.Equal(t, testGroup.Description, getResponse.Group.Description)
	assert.Equal(t, testGroup.IncludeInIdToken, getResponse.Group.IncludeInIdToken)
	assert.Equal(t, testGroup.IncludeInAccessToken, getResponse.Group.IncludeInAccessToken)
	assert.NotNil(t, getResponse.Group.CreatedAt)
	assert.NotNil(t, getResponse.Group.UpdatedAt)
	assert.GreaterOrEqual(t, getResponse.Group.MemberCount, 0, "MemberCount should be non-negative")
}

func TestAPIGroupGet_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get non-existent group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/99999"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupGet_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		groupId        string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusOK}, // This matches /groups route instead of /groups/{id}
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + tc.groupId
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupGet_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIGroupGet_MemberCountAccuracy(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create test users
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@singlegroupmembercount.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Get group without members first
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful with 0 members
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var getResponse api.GetGroupResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	assert.Equal(t, 0, getResponse.Group.MemberCount, "Group should have 0 members initially")

	// Setup: Add user to group
	userGroup := &models.UserGroup{
		UserId:  testUser.Id,
		GroupId: testGroup.Id,
	}
	err = database.CreateUserGroup(nil, userGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUserGroup(nil, userGroup.Id)
	}()

	// Test: Get group with member
	resp2 := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()

	// Assert: Response should be successful with 1 member
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	var getResponse2 api.GetGroupResponse
	err = json.NewDecoder(resp2.Body).Decode(&getResponse2)
	assert.NoError(t, err)

	assert.Equal(t, 1, getResponse2.Group.MemberCount, "Group should have 1 member after adding user")
}
