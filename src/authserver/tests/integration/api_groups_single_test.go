package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

// TestAPIGroupGet tests the GET /api/v1/admin/groups/{id} endpoint
func TestAPIGroupGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroupUnique(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Get group by ID
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

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
}

func TestAPIGroupGet_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get non-existent group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/99999"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

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
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupGet_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroupUnique(t)
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
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}