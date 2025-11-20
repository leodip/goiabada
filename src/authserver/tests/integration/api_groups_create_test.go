package integrationtests

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

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
	defer func() { _ = resp.Body.Close() }()

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
	assert.Equal(t, float64(0), group["memberCount"], "New group should have 0 members")

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
			defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

	// Assert response
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"].(map[string]interface{})["message"].(string), "Invalid")
}