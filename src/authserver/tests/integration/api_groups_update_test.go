package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIGroupUpdatePut tests the PUT /api/v1/admin/groups/{id} endpoint
func TestAPIGroupUpdatePut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroupUnique(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Update group
	updateReq := api.UpdateGroupRequest{
		GroupIdentifier:      "updated-group-" + gofakeit.LetterN(6),
		Description:          "Updated group description",
		IncludeInIdToken:     false,
		IncludeInAccessToken: true,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateGroupResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Response should reflect updates
	assert.Equal(t, testGroup.Id, updateResponse.Group.Id)
	assert.Equal(t, updateReq.GroupIdentifier, updateResponse.Group.GroupIdentifier)
	assert.Equal(t, updateReq.Description, updateResponse.Group.Description)
	assert.Equal(t, updateReq.IncludeInIdToken, updateResponse.Group.IncludeInIdToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updateResponse.Group.IncludeInAccessToken)
	assert.GreaterOrEqual(t, updateResponse.Group.MemberCount, 0, "MemberCount should be non-negative")

	// Verify changes were persisted to database
	updatedGroup, err := database.GetGroupById(nil, testGroup.Id)
	assert.NoError(t, err)
	assert.NotNil(t, updatedGroup)
	assert.Equal(t, updateReq.GroupIdentifier, updatedGroup.GroupIdentifier)
	assert.Equal(t, updateReq.Description, updatedGroup.Description)
	assert.Equal(t, updateReq.IncludeInIdToken, updatedGroup.IncludeInIdToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updatedGroup.IncludeInAccessToken)
}

func TestAPIGroupUpdatePut_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroupUnique(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	testCases := []struct {
		name           string
		request        api.UpdateGroupRequest
		expectedStatus int
	}{
		{
			"empty group identifier",
			api.UpdateGroupRequest{
				GroupIdentifier: "",
				Description:     "Valid description",
			},
			http.StatusBadRequest,
		},
		{
			"description too long",
			api.UpdateGroupRequest{
				GroupIdentifier: "valid-identifier",
				Description:     strings.Repeat("a", 101), // 101 characters, exceeds 100 limit
			},
			http.StatusBadRequest,
		},
		{
			"invalid identifier format",
			api.UpdateGroupRequest{
				GroupIdentifier: "invalid identifier with spaces",
				Description:     "Valid description",
			},
			http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
			resp := makeAPIRequest(t, "PUT", url, accessToken, tc.request)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupUpdatePut_DuplicateIdentifier(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create two test groups
	testGroup1 := createTestGroupUnique(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup1.Id)
	}()

	testGroup2 := createTestGroupUnique(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup2.Id)
	}()

	// Test: Try to update group2 with group1's identifier
	updateReq := api.UpdateGroupRequest{
		GroupIdentifier: testGroup1.GroupIdentifier,
		Description:     "Updated description",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup2.Id, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return validation error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIGroupUpdatePut_SameIdentifier(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroupUnique(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Update group with same identifier (should be allowed)
	updateReq := api.UpdateGroupRequest{
		GroupIdentifier:      testGroup.GroupIdentifier, // Same identifier
		Description:          "Updated description",
		IncludeInIdToken:     !testGroup.IncludeInIdToken,
		IncludeInAccessToken: !testGroup.IncludeInAccessToken,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateGroupResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Should allow update with same identifier
	assert.Equal(t, updateReq.GroupIdentifier, updateResponse.Group.GroupIdentifier)
	assert.Equal(t, updateReq.Description, updateResponse.Group.Description)
}

func TestAPIGroupUpdatePut_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update non-existent group
	updateReq := api.UpdateGroupRequest{
		GroupIdentifier: "valid-identifier",
		Description:     "Valid description",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/99999"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupUpdatePut_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	updateReq := api.UpdateGroupRequest{
		GroupIdentifier: "valid-identifier",
		Description:     "Valid description",
	}

	testCases := []struct {
		name           string
		groupId        string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusMethodNotAllowed}, // No PUT route matches /groups/
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + tc.groupId
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupUpdatePut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroupUnique(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
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

func TestAPIGroupUpdatePut_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroupUnique(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIGroupUpdatePut_WhitespaceHandling(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroupUnique(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Update with whitespace that should fail validation
	updateReq := api.UpdateGroupRequest{
		GroupIdentifier:      "  whitespace-identifier-" + gofakeit.LetterN(4) + "  ",
		Description:          "  Whitespace description  ",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should fail validation due to whitespace in identifier
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Test with properly trimmed identifier
	updateReq.GroupIdentifier = strings.TrimSpace(updateReq.GroupIdentifier)
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp2.Body.Close()

	// Assert: Should succeed with trimmed identifier
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// Parse response
	var updateResponse api.UpdateGroupResponse
	err := json.NewDecoder(resp2.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Values should be trimmed in response
	assert.Equal(t, strings.TrimSpace(updateReq.GroupIdentifier), updateResponse.Group.GroupIdentifier)
	assert.Equal(t, "Whitespace description", updateResponse.Group.Description)
}

func TestAPIGroupUpdatePut_BooleanFlags(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group with specific initial values
	testGroup := &models.Group{
		GroupIdentifier:      "test-bool-group-" + gofakeit.LetterN(8),
		Description:          "Test boolean flags",
		IncludeInIdToken:     false,
		IncludeInAccessToken: false,
	}
	err := database.CreateGroup(nil, testGroup)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	testCases := []struct {
		name                 string
		includeInIdToken     bool
		includeInAccessToken bool
	}{
		{"both false", false, false},
		{"id token only", true, false},
		{"access token only", false, true},
		{"both true", true, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			updateReq := api.UpdateGroupRequest{
				GroupIdentifier:      testGroup.GroupIdentifier,
				Description:          "Updated for " + tc.name,
				IncludeInIdToken:     tc.includeInIdToken,
				IncludeInAccessToken: tc.includeInAccessToken,
			}

			url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer resp.Body.Close()

			// Assert: Response should be successful
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			// Parse response
			var updateResponse api.UpdateGroupResponse
			err := json.NewDecoder(resp.Body).Decode(&updateResponse)
			assert.NoError(t, err)

			// Assert: Boolean values should be preserved
			assert.Equal(t, tc.includeInIdToken, updateResponse.Group.IncludeInIdToken)
			assert.Equal(t, tc.includeInAccessToken, updateResponse.Group.IncludeInAccessToken)
		})
	}
}

func TestAPIGroupUpdatePut_MemberCountInResponse(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroupUnique(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create test user and add to group
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@updatemembercount.test",
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
	defer func() {
		_ = database.DeleteUserGroup(nil, userGroup.Id)
	}()

	// Test: Update group (member count should be preserved in response)
	updateReq := api.UpdateGroupRequest{
		GroupIdentifier:      testGroup.GroupIdentifier + "-updated",
		Description:          "Updated description",
		IncludeInIdToken:     !testGroup.IncludeInIdToken,
		IncludeInAccessToken: !testGroup.IncludeInAccessToken,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateGroupResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Response should include correct member count
	assert.Equal(t, 1, updateResponse.Group.MemberCount, "Update response should include current member count")

	// Assert: Updated fields should be correct
	assert.Equal(t, updateReq.GroupIdentifier, updateResponse.Group.GroupIdentifier)
	assert.Equal(t, updateReq.Description, updateResponse.Group.Description)
	assert.Equal(t, updateReq.IncludeInIdToken, updateResponse.Group.IncludeInIdToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updateResponse.Group.IncludeInAccessToken)
}