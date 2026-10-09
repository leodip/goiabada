package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGroupCreatePost_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Create request data
	reqData := map[string]interface{}{
		"groupIdentifier":      "test-group-" + fake.LetterN(6),
		"description":          "Test Group Description",
		"includeInIdToken":     true,
		"includeInAccessToken": false,
	}

	// Make POST request
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqData)
	defer func() { _ = resp.Body.Close() }()

	// Assert response
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)

	// Verify response structure
	assert.Contains(t, response, "group")
	group := response["group"].(map[string]interface{})
	assert.Equal(t, reqData["groupIdentifier"], group["groupIdentifier"])
	assert.Equal(t, reqData["description"], group["description"])
	assert.Equal(t, reqData["includeInIdToken"], group["includeInIdToken"])
	assert.Equal(t, reqData["includeInAccessToken"], group["includeInAccessToken"])
	assert.NotZero(t, group["id"])
	assert.InDelta(t, 0, group["memberCount"], 0, "New group should have 0 members")

	// Clean up - delete the created group
	groupId := int64(group["id"].(float64))
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, groupId)
	}()
}

func TestHandleGroupCreatePost_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups"

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
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			var response map[string]interface{}
			err := json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)
			assert.Contains(t, response["error_description"].(string), tc.expectedError)
		})
	}
}

func TestHandleGroupCreatePost_DuplicateGroupIdentifier(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Create a group first
	existingGroup := &record.Group{
		GroupIdentifier:      "existing-group-" + fake.LetterN(6),
		Description:          "Existing Group",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}
	err := database.CreateGroup(context.Background(), nil, existingGroup)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, existingGroup.Id)
	}()

	// Try to create another group with same identifier
	reqData := map[string]interface{}{
		"groupIdentifier":      existingGroup.GroupIdentifier,
		"description":          "Duplicate Group",
		"includeInIdToken":     false,
		"includeInAccessToken": true,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqData)
	defer func() { _ = resp.Body.Close() }()

	// Assert response
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	assert.Contains(t, response["error_description"].(string), "The group identifier is already in use")
}

// TestHandleGroupCreatePost_AngleBracketsRejected pins the reject that replaced the strip: this
// description used to be stored as "Test Description" with a 201, the script tag silently dropped
// (#275).
func TestHandleGroupCreatePost_AngleBracketsRejected(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	identifier := "test-group-" + fake.LetterN(6)
	reqData := map[string]interface{}{
		"groupIdentifier":      identifier, // Valid identifier (no spaces) to pass validation
		"description":          "  <script>alert('xss')</script>Test Description  ",
		"includeInIdToken":     true,
		"includeInAccessToken": false,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqData)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp api.ErrorResponse
	err := json.NewDecoder(resp.Body).Decode(&errResp)
	require.NoError(t, err)
	assert.Equal(t, "validator.description.angle_brackets", errResp.ErrorCode)

	// Nothing was created.
	stored, err := database.GetGroupByGroupIdentifier(context.Background(), nil, identifier)
	require.NoError(t, err)
	assert.Nil(t, stored)
}

// TestHandleGroupCreatePost_AmpersandsAndQuotesStoredVerbatim is the accepted twin: a
// description the validator does not refuse is trimmed and otherwise stored byte for byte.
func TestHandleGroupCreatePost_AmpersandsAndQuotesStoredVerbatim(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	identifier := "test-group-" + fake.LetterN(6)
	reqData := map[string]interface{}{
		"groupIdentifier":      identifier,
		"description":          `  Tom & Jerry said "hi"  `,
		"includeInIdToken":     true,
		"includeInAccessToken": false,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "POST", url, accessToken, reqData)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)

	group := response["group"].(map[string]interface{})
	assert.Equal(t, `Tom & Jerry said "hi"`, group["description"])

	groupId := int64(group["id"].(float64))
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, groupId)
	}()

	stored, err := database.GetGroupById(context.Background(), nil, groupId)
	require.NoError(t, err)
	assert.Equal(t, `Tom & Jerry said "hi"`, stored.Description)
}

func TestHandleGroupCreatePost_Unauthorized(t *testing.T) {
	reqData := map[string]interface{}{
		"groupIdentifier":      "test-group",
		"description":          "Test Description",
		"includeInIdToken":     true,
		"includeInAccessToken": false,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups"
	resp := makeAPIRequest(t, "POST", url, "", reqData) // Empty access token
	defer func() { _ = resp.Body.Close() }()

	// Assert response
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHandleGroupCreatePost_InvalidJSON(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Invalid JSON body
	invalidJSON := `{"groupIdentifier": "test", "description": }`

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups"
	req, err := http.NewRequest("POST", url, strings.NewReader(invalidJSON))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert response
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	assert.Contains(t, response["error_description"].(string), "Invalid")
}
