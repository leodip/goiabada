package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIGroupAttributesGet tests the GET /api/v1/admin/groups/{id}/attributes endpoint
func TestAPIGroupAttributesGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Setup: Create test attributes
	attr1 := createTestGroupAttribute(t, testGroup.ID, "department", "engineering")
	attr2 := createTestGroupAttribute(t, testGroup.ID, "role", "developer")
	defer func() {
		_ = database.DeleteGroupAttribute(context.Background(), nil, attr1.ID)
		_ = database.DeleteGroupAttribute(context.Background(), nil, attr2.ID)
	}()

	// Test: Get group attributes
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetGroupAttributesResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: Should return both attributes
	assert.Len(t, getResponse.Attributes, 2)

	// Create a map for easier assertion
	attrMap := make(map[string]api.GroupAttributeResponse)
	for _, attr := range getResponse.Attributes {
		attrMap[attr.Key] = attr
	}

	// Verify both attributes are present
	deptAttr, exists := attrMap["department"]
	assert.True(t, exists)
	assert.Equal(t, "engineering", deptAttr.Value)
	assert.True(t, deptAttr.IncludeInIDToken)
	assert.False(t, deptAttr.IncludeInAccessToken)
	assert.Equal(t, testGroup.ID, deptAttr.GroupID)

	roleAttr, exists := attrMap["role"]
	assert.True(t, exists)
	assert.Equal(t, "developer", roleAttr.Value)
}

func TestAPIGroupAttributesGet_EmptyAttributes(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group without attributes
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Get group attributes for group with no attributes
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetGroupAttributesResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: Should return empty attributes array
	assert.Empty(t, getResponse.Attributes)
}

func TestAPIGroupAttributesGet_GroupNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get attributes for non-existent group
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/99999/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupAttributesGet_InvalidID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		groupID        string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		// An empty segment matches no route, so the group answers 404 (#462 decision 4).
		{"empty ID", "", http.StatusNotFound},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + tc.groupID + "/attributes"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupAttributesGet_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.ID, 10) + "/attributes"
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIGroupAttributeGet tests the GET /api/v1/admin/group-attributes/{id} endpoint
func TestAPIGroupAttributeGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Setup: Create test attribute
	attr := createTestGroupAttribute(t, testGroup.ID, "team", "backend")
	defer func() {
		_ = database.DeleteGroupAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Get specific group attribute
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.ID, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetGroupAttributeResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: Should return the correct attribute
	assert.Equal(t, attr.ID, getResponse.Attribute.ID)
	assert.Equal(t, "team", getResponse.Attribute.Key)
	assert.Equal(t, "backend", getResponse.Attribute.Value)
	assert.True(t, getResponse.Attribute.IncludeInIDToken)
	assert.False(t, getResponse.Attribute.IncludeInAccessToken)
	assert.Equal(t, testGroup.ID, getResponse.Attribute.GroupID)
}

func TestAPIGroupAttributeGet_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get non-existent attribute
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/99999"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupAttributeGet_InvalidID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		attributeID    string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusMethodNotAllowed},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/" + tc.attributeID
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupAttributeGet_Unauthorized(t *testing.T) {
	// Setup: Create test group and attribute
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	attr := createTestGroupAttribute(t, testGroup.ID, "level", "senior")
	defer func() {
		_ = database.DeleteGroupAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.ID, 10)
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIGroupAttributeCreatePost tests the POST /api/v1/admin/group-attributes endpoint
func TestAPIGroupAttributeCreatePost_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Test: Create group attribute
	createReq := api.CreateGroupAttributeRequest{
		Key:                  "location",
		Value:                "San Francisco",
		IncludeInIDToken:     true,
		IncludeInAccessToken: true,
		GroupID:              testGroup.ID,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes"
	resp := makeAPIRequest(t, "POST", url, accessToken, createReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var createResponse api.CreateGroupAttributeResponse
	err := json.NewDecoder(resp.Body).Decode(&createResponse)
	require.NoError(t, err)

	// Assert: Response should match request
	assert.Equal(t, createReq.Key, createResponse.Attribute.Key)
	assert.Equal(t, createReq.Value, createResponse.Attribute.Value)
	assert.Equal(t, createReq.IncludeInIDToken, createResponse.Attribute.IncludeInIDToken)
	assert.Equal(t, createReq.IncludeInAccessToken, createResponse.Attribute.IncludeInAccessToken)
	assert.Equal(t, createReq.GroupID, createResponse.Attribute.GroupID)
	assert.Positive(t, createResponse.Attribute.ID)

	// Cleanup: Delete created attribute
	defer func() {
		if createResponse.Attribute.ID > 0 {
			_ = database.DeleteGroupAttribute(context.Background(), nil, createResponse.Attribute.ID)
		}
	}()

	// Verify attribute was created in database
	createdAttr, err := database.GetGroupAttributeByID(context.Background(), nil, createResponse.Attribute.ID)
	require.NoError(t, err)
	assert.NotNil(t, createdAttr)
	assert.Equal(t, createReq.Key, createdAttr.Key)
	assert.Equal(t, createReq.Value, createdAttr.Value)
}

func TestAPIGroupAttributeCreatePost_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	testCases := []struct {
		name           string
		request        api.CreateGroupAttributeRequest
		expectedStatus int
	}{
		{
			"missing key",
			api.CreateGroupAttributeRequest{
				Value:   "test",
				GroupID: testGroup.ID,
			},
			http.StatusBadRequest,
		},
		{
			"empty key",
			api.CreateGroupAttributeRequest{
				Key:     "",
				Value:   "test",
				GroupID: testGroup.ID,
			},
			http.StatusBadRequest,
		},
		{
			"value too long",
			api.CreateGroupAttributeRequest{
				Key:     "test_key",
				Value:   string(make([]byte, 251)), // 251 characters, exceeds 250 limit
				GroupID: testGroup.ID,
			},
			http.StatusBadRequest,
		},
		{
			"invalid key format",
			api.CreateGroupAttributeRequest{
				Key:     "invalid key with spaces",
				Value:   "test",
				GroupID: testGroup.ID,
			},
			http.StatusBadRequest,
		},
		{
			"group not found",
			api.CreateGroupAttributeRequest{
				Key:     "valid_key",
				Value:   "test",
				GroupID: 99999,
			},
			http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes"
			resp := makeAPIRequest(t, "POST", url, accessToken, tc.request)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupAttributeCreatePost_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Invalid JSON
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes"
	req, err := http.NewRequest("POST", url, nil)
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

func TestAPIGroupAttributeCreatePost_Unauthorized(t *testing.T) {
	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes"
	req, err := http.NewRequest("POST", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIGroupAttributeUpdatePut tests the PUT /api/v1/admin/group-attributes/{id} endpoint
func TestAPIGroupAttributeUpdatePut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Setup: Create test attribute
	attr := createTestGroupAttribute(t, testGroup.ID, "status", "active")
	defer func() {
		_ = database.DeleteGroupAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Update attribute
	updateReq := api.UpdateGroupAttributeRequest{
		Key:                  "status",
		Value:                "inactive",
		IncludeInIDToken:     false,
		IncludeInAccessToken: true,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.ID, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateGroupAttributeResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)

	// Assert: Response should reflect updates
	assert.Equal(t, attr.ID, updateResponse.Attribute.ID)
	assert.Equal(t, updateReq.Key, updateResponse.Attribute.Key)
	assert.Equal(t, updateReq.Value, updateResponse.Attribute.Value)
	assert.Equal(t, updateReq.IncludeInIDToken, updateResponse.Attribute.IncludeInIDToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updateResponse.Attribute.IncludeInAccessToken)

	// Verify changes were persisted to database
	updatedAttr, err := database.GetGroupAttributeByID(context.Background(), nil, attr.ID)
	require.NoError(t, err)
	assert.NotNil(t, updatedAttr)
	assert.Equal(t, updateReq.Key, updatedAttr.Key)
	assert.Equal(t, updateReq.Value, updatedAttr.Value)
	assert.Equal(t, updateReq.IncludeInIDToken, updatedAttr.IncludeInIDToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updatedAttr.IncludeInAccessToken)
}

func TestAPIGroupAttributeUpdatePut_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update non-existent attribute
	updateReq := api.UpdateGroupAttributeRequest{
		Key:   "test_key",
		Value: "test_value",
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/99999"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupAttributeUpdatePut_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group and attribute
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	attr := createTestGroupAttribute(t, testGroup.ID, "test_key", "test_value")
	defer func() {
		_ = database.DeleteGroupAttribute(context.Background(), nil, attr.ID)
	}()

	testCases := []struct {
		name           string
		request        api.UpdateGroupAttributeRequest
		expectedStatus int
	}{
		{
			"missing key",
			api.UpdateGroupAttributeRequest{
				Value: "test",
			},
			http.StatusBadRequest,
		},
		{
			"empty key",
			api.UpdateGroupAttributeRequest{
				Key:   "",
				Value: "test",
			},
			http.StatusBadRequest,
		},
		{
			"value too long",
			api.UpdateGroupAttributeRequest{
				Key:   "valid_key",
				Value: string(make([]byte, 251)), // 251 characters
			},
			http.StatusBadRequest,
		},
		{
			"invalid key format",
			api.UpdateGroupAttributeRequest{
				Key:   "invalid key with spaces",
				Value: "test",
			},
			http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.ID, 10)
			resp := makeAPIRequest(t, "PUT", url, accessToken, tc.request)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupAttributeUpdatePut_InvalidID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	updateReq := api.UpdateGroupAttributeRequest{
		Key:   "test_key",
		Value: "test_value",
	}

	testCases := []struct {
		name           string
		attributeID    string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusMethodNotAllowed},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/" + tc.attributeID
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupAttributeUpdatePut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group and attribute
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	attr := createTestGroupAttribute(t, testGroup.ID, "test_key", "test_value")
	defer func() {
		_ = database.DeleteGroupAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Invalid JSON
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.ID, 10)
	req, err := http.NewRequest("PUT", url, nil)
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

func TestAPIGroupAttributeUpdatePut_Unauthorized(t *testing.T) {
	// Setup: Create test group and attribute
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	attr := createTestGroupAttribute(t, testGroup.ID, "test_key", "test_value")
	defer func() {
		_ = database.DeleteGroupAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.ID, 10)
	req, err := http.NewRequest("PUT", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIGroupAttributeDelete tests the DELETE /api/v1/admin/group-attributes/{id} endpoint
func TestAPIGroupAttributeDelete_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	// Setup: Create test attribute
	attr := createTestGroupAttribute(t, testGroup.ID, "temp_attr", "temp_value")

	// Test: Delete attribute
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.ID, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var deleteResponse api.SuccessResponse
	err := json.NewDecoder(resp.Body).Decode(&deleteResponse)
	require.NoError(t, err)

	// Assert: Success response
	assert.True(t, deleteResponse.Success)

	// Verify attribute was actually deleted from database
	deletedAttr, err := database.GetGroupAttributeByID(context.Background(), nil, attr.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedAttr)
}

func TestAPIGroupAttributeDelete_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Delete non-existent attribute
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/99999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupAttributeDelete_InvalidID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		attributeID    string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusMethodNotAllowed},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/" + tc.attributeID
			resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupAttributeDelete_Unauthorized(t *testing.T) {
	// Setup: Create test group and attribute
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(context.Background(), nil, testGroup.ID)
	}()

	attr := createTestGroupAttribute(t, testGroup.ID, "persistent", "value")
	defer func() {
		_ = database.DeleteGroupAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.ID, 10)
	req, err := http.NewRequest("DELETE", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify attribute was not deleted
	stillExists, err := database.GetGroupAttributeByID(context.Background(), nil, attr.ID)
	require.NoError(t, err)
	assert.NotNil(t, stillExists)
}

// Helper function to create a test group attribute
func createTestGroupAttribute(t *testing.T, groupID int64, key, value string) *record.GroupAttribute {
	attr := &record.GroupAttribute{
		Key:                  key,
		Value:                value,
		IncludeInIDToken:     true,
		IncludeInAccessToken: false,
		GroupID:              groupID,
	}
	err := database.CreateGroupAttribute(context.Background(), nil, attr)
	assert.NoError(t, err)
	return attr
}

// TestAPIGroupAttribute_AngleBracketsRejected pins the reject on both wiring points, create and
// update: each carries its own check (#275).
func TestAPIGroupAttribute_AngleBracketsRejected(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	testGroup := createTestGroup(t)
	defer func() { _ = database.DeleteGroup(context.Background(), nil, testGroup.ID) }()

	attr := createTestGroupAttribute(t, testGroup.ID, "status", "active")
	defer func() { _ = database.DeleteGroupAttribute(context.Background(), nil, attr.ID) }()

	base := appConfig.AuthServer.BaseURL + "/api/v1/admin/group-attributes"

	t.Run("create", func(t *testing.T) {
		resp := makeAPIRequest(t, "POST", base, accessToken, api.CreateGroupAttributeRequest{
			Key:     "location",
			Value:   "<b>San Francisco</b>",
			GroupID: testGroup.ID,
		})
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		var errResp api.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		assert.Equal(t, "validator.attribute.value_angle_brackets", errResp.ErrorCode)
	})

	t.Run("update", func(t *testing.T) {
		resp := makeAPIRequest(t, "PUT", base+"/"+strconv.FormatInt(attr.ID, 10), accessToken,
			api.UpdateGroupAttributeRequest{Key: "status", Value: "a < b"})
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		var errResp api.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		assert.Equal(t, "validator.attribute.value_angle_brackets", errResp.ErrorCode)

		stored, err := database.GetGroupAttributeByID(context.Background(), nil, attr.ID)
		require.NoError(t, err)
		assert.Equal(t, "active", stored.Value)
	})
}

// TestAPIGroupAttribute_AmpersandsAndQuotesStoredVerbatim is the accepted twin, on both wiring
// points like its rejected counterpart above: create and update assign the value independently, so
// a rewrite installed on one of them is invisible to a test that only exercises the other.
// Attribute values are not trimmed, so the surrounding spaces come back too.
func TestAPIGroupAttribute_AmpersandsAndQuotesStoredVerbatim(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	testGroup := createTestGroup(t)
	defer func() { _ = database.DeleteGroup(context.Background(), nil, testGroup.ID) }()

	value := `  R&D "phase 2"  `
	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/admin/group-attributes",
		accessToken, api.CreateGroupAttributeRequest{Key: "motto", Value: value, GroupID: testGroup.ID})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var createResponse api.CreateGroupAttributeResponse
	err := json.NewDecoder(resp.Body).Decode(&createResponse)
	require.NoError(t, err)
	assert.Equal(t, value, createResponse.Attribute.Value)

	stored, err := database.GetGroupAttributeByID(context.Background(), nil, createResponse.Attribute.ID)
	require.NoError(t, err)
	assert.Equal(t, value, stored.Value)
	defer func() { _ = database.DeleteGroupAttribute(context.Background(), nil, createResponse.Attribute.ID) }()

	updated := `  AT&T "phase 3"  `
	updateResp := makeAPIRequest(t, "PUT", appConfig.AuthServer.BaseURL+"/api/v1/admin/group-attributes/"+
		strconv.FormatInt(createResponse.Attribute.ID, 10), accessToken,
		api.UpdateGroupAttributeRequest{Key: "motto", Value: updated})
	defer func() { _ = updateResp.Body.Close() }()

	assert.Equal(t, http.StatusOK, updateResp.StatusCode)

	var updateResponse api.UpdateGroupAttributeResponse
	err = json.NewDecoder(updateResp.Body).Decode(&updateResponse)
	require.NoError(t, err)
	assert.Equal(t, updated, updateResponse.Attribute.Value)

	stored, err = database.GetGroupAttributeByID(context.Background(), nil, createResponse.Attribute.ID)
	require.NoError(t, err)
	assert.Equal(t, updated, stored.Value)
}
