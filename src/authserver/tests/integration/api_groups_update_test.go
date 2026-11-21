package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIGroupUpdatePut tests the PUT /api/v1/admin/groups/{id} endpoint
func TestAPIGroupUpdatePut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Update group
	updateReq := api.UpdateGroupRequest{
		GroupIdentifier:      "updated-group-" + fake.LetterN(6),
		Description:          "Updated group description",
		IncludeInIDToken:     false,
		IncludeInAccessToken: true,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateGroupResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)

	// Assert: Response should reflect updates
	assert.Equal(t, testGroup.ID, updateResponse.Group.ID)
	assert.Equal(t, updateReq.GroupIdentifier, updateResponse.Group.GroupIdentifier)
	assert.Equal(t, updateReq.Description, updateResponse.Group.Description)
	assert.Equal(t, updateReq.IncludeInIDToken, updateResponse.Group.IncludeInIDToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updateResponse.Group.IncludeInAccessToken)
	assert.GreaterOrEqual(t, updateResponse.Group.MemberCount, 0, "MemberCount should be non-negative")

	// Verify changes were persisted to database
	updatedGroup, err := database.GetGroupByID(context.Background(), nil, testGroup.ID)
	require.NoError(t, err)
	assert.NotNil(t, updatedGroup)
	assert.Equal(t, updateReq.GroupIdentifier, updatedGroup.GroupIdentifier)
	assert.Equal(t, updateReq.Description, updatedGroup.Description)
	assert.Equal(t, updateReq.IncludeInIDToken, updatedGroup.IncludeInIDToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updatedGroup.IncludeInAccessToken)
}

func TestAPIGroupUpdatePut_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
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
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10)
			resp := makeAPIRequest(t, "PUT", url, accessToken, tc.request)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupUpdatePut_DuplicateIdentifier(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create two test groups
	testGroup1 := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup1.ID)
	}()

	testGroup2 := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup2.ID)
	}()

	// Test: Try to update group2 with group1's identifier
	updateReq := api.UpdateGroupRequest{
		GroupIdentifier: testGroup1.GroupIdentifier,
		Description:     "Updated description",
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup2.ID, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return validation error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIGroupUpdatePut_SameIdentifier(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Update group with same identifier (should be allowed)
	updateReq := api.UpdateGroupRequest{
		GroupIdentifier:      testGroup.GroupIdentifier, // Same identifier
		Description:          "Updated description",
		IncludeInIDToken:     !testGroup.IncludeInIDToken,
		IncludeInAccessToken: !testGroup.IncludeInAccessToken,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateGroupResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)

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

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/99999"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupUpdatePut_InvalidID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	updateReq := api.UpdateGroupRequest{
		GroupIdentifier: "valid-identifier",
		Description:     "Valid description",
	}

	testCases := []struct {
		name           string
		groupID        string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusMethodNotAllowed}, // No PUT route matches /groups/
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + tc.groupID
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupUpdatePut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Invalid JSON
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10)
	req, err := http.NewRequest("PUT", url, nil) // No body
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIGroupUpdatePut_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10)
	req, err := http.NewRequest("PUT", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIGroupUpdatePut_WhitespaceHandling(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Update with whitespace that should fail validation
	updateReq := api.UpdateGroupRequest{
		GroupIdentifier:      "  whitespace-identifier-" + fake.LetterN(4) + "  ",
		Description:          "  Whitespace description  ",
		IncludeInIDToken:     true,
		IncludeInAccessToken: false,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should fail validation due to whitespace in identifier
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Test with properly trimmed identifier
	updateReq.GroupIdentifier = strings.TrimSpace(updateReq.GroupIdentifier)
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp2.Body.Close() }()

	// Assert: Should succeed with trimmed identifier
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// Parse response
	var updateResponse api.UpdateGroupResponse
	err := json.NewDecoder(resp2.Body).Decode(&updateResponse)
	require.NoError(t, err)

	// Assert: Values should be trimmed in response
	assert.Equal(t, strings.TrimSpace(updateReq.GroupIdentifier), updateResponse.Group.GroupIdentifier)
	assert.Equal(t, "Whitespace description", updateResponse.Group.Description)
}

func TestAPIGroupUpdatePut_BooleanFlags(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group with specific initial values
	testGroup := &record.Group{
		GroupIdentifier:      "test-bool-group-" + fake.LetterN(8),
		Description:          "Test boolean flags",
		IncludeInIDToken:     false,
		IncludeInAccessToken: false,
	}
	err := database.CreateGroup(context.Background(), nil, testGroup)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	testCases := []struct {
		name                 string
		includeInIDToken     bool
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
				IncludeInIDToken:     tc.includeInIDToken,
				IncludeInAccessToken: tc.includeInAccessToken,
			}

			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10)
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer func() { _ = resp.Body.Close() }()

			// Assert: Response should be successful
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			// Parse response
			var updateResponse api.UpdateGroupResponse
			err := json.NewDecoder(resp.Body).Decode(&updateResponse)
			require.NoError(t, err)

			// Assert: Boolean values should be preserved
			assert.Equal(t, tc.includeInIDToken, updateResponse.Group.IncludeInIDToken)
			assert.Equal(t, tc.includeInAccessToken, updateResponse.Group.IncludeInAccessToken)
		})
	}
}

func TestAPIGroupUpdatePut_MemberCountInResponse(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Setup: Create test user and add to group
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@updatemembercount.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	userGroup := &record.UserGroup{
		UserID:  testUser.ID,
		GroupID: testGroup.ID,
	}
	err = database.CreateUserGroup(context.Background(), nil, userGroup)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUserGroup(context.Background(), nil, userGroup.ID)
	}()

	// Test: Update group (member count should be preserved in response)
	updateReq := api.UpdateGroupRequest{
		GroupIdentifier:      testGroup.GroupIdentifier + "-updated",
		Description:          "Updated description",
		IncludeInIDToken:     !testGroup.IncludeInIDToken,
		IncludeInAccessToken: !testGroup.IncludeInAccessToken,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateGroupResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)

	// Assert: Response should include correct member count
	assert.Equal(t, 1, updateResponse.Group.MemberCount, "Update response should include current member count")

	// Assert: Updated fields should be correct
	assert.Equal(t, updateReq.GroupIdentifier, updateResponse.Group.GroupIdentifier)
	assert.Equal(t, updateReq.Description, updateResponse.Group.Description)
	assert.Equal(t, updateReq.IncludeInIDToken, updateResponse.Group.IncludeInIDToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updateResponse.Group.IncludeInAccessToken)
}

// TestAPIGroupUpdatePut_AngleBracketsRejected covers the update handler's own description check,
// which is a separate wiring point from the create handler's (#275).
func TestAPIGroupUpdatePut_AngleBracketsRejected(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	testGroup := createTestGroup(t)
	defer func() { _ = database.DeleteGroup(context.Background(), nil, testGroup.ID) }()

	updateReq := api.UpdateGroupRequest{
		GroupIdentifier:      testGroup.GroupIdentifier,
		Description:          "1 < 2 and 3 > 2",
		IncludeInIDToken:     true,
		IncludeInAccessToken: true,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "validator.description.angle_brackets", errResp.ErrorCode)

	stored, err := database.GetGroupByID(context.Background(), nil, testGroup.ID)
	require.NoError(t, err)
	assert.Equal(t, testGroup.Description, stored.Description)
}

// TestAPIGroupUpdatePut_AmpersandsAndQuotesStoredVerbatim is the accepted twin.
func TestAPIGroupUpdatePut_AmpersandsAndQuotesStoredVerbatim(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	testGroup := createTestGroup(t)
	defer func() { _ = database.DeleteGroup(context.Background(), nil, testGroup.ID) }()

	updateReq := api.UpdateGroupRequest{
		GroupIdentifier:      testGroup.GroupIdentifier,
		Description:          `R&D "phase 2"`,
		IncludeInIDToken:     true,
		IncludeInAccessToken: true,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	stored, err := database.GetGroupByID(context.Background(), nil, testGroup.ID)
	require.NoError(t, err)
	assert.Equal(t, `R&D "phase 2"`, stored.Description)
}
