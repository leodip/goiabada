package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

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

	// Debug: Read raw response body first
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	t.Logf("Raw response body: %s", string(body))
	
	// Parse response
	var getResponse api.GetGroupsResponse
	err = json.Unmarshal(body, &getResponse)
	assert.NoError(t, err)

	// Debug: Print the response to see what we're getting
	t.Logf("Response Groups: %+v", getResponse.Groups)
	t.Logf("Groups is nil: %v", getResponse.Groups == nil)
	t.Logf("Groups length: %d", len(getResponse.Groups))

	// Let's also test manual JSON unmarshaling
	var testResp map[string]interface{}
	err = json.Unmarshal(body, &testResp)
	assert.NoError(t, err)
	t.Logf("Raw map parsing - groups value: %+v", testResp["groups"])
	t.Logf("Raw map parsing - groups type: %T", testResp["groups"])

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