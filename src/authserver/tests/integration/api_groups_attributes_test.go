package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIGroupAttributesGet tests the GET /api/v1/admin/groups/{id}/attributes endpoint
func TestAPIGroupAttributesGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create test attributes
	attr1 := createTestGroupAttribute(t, testGroup.Id, "department", "engineering")
	attr2 := createTestGroupAttribute(t, testGroup.Id, "role", "developer")
	defer func() {
		_ = database.DeleteGroupAttribute(nil, attr1.Id)
		_ = database.DeleteGroupAttribute(nil, attr2.Id)
	}()

	// Test: Get group attributes
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetGroupAttributesResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

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
	assert.True(t, deptAttr.IncludeInIdToken)
	assert.False(t, deptAttr.IncludeInAccessToken)
	assert.Equal(t, testGroup.Id, deptAttr.GroupId)

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
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Get group attributes for group with no attributes
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetGroupAttributesResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return empty attributes array
	assert.Len(t, getResponse.Attributes, 0)
}

func TestAPIGroupAttributesGet_GroupNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get attributes for non-existent group
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/99999/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupAttributesGet_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		groupId        string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusBadRequest},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + tc.groupId + "/attributes"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupAttributesGet_Unauthorized(t *testing.T) {
	// Setup: Create test group
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/groups/" + strconv.FormatInt(testGroup.Id, 10) + "/attributes"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

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
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create test attribute
	attr := createTestGroupAttribute(t, testGroup.Id, "team", "backend")
	defer func() {
		_ = database.DeleteGroupAttribute(nil, attr.Id)
	}()

	// Test: Get specific group attribute
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.Id, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetGroupAttributeResponse
	err := json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return the correct attribute
	assert.Equal(t, attr.Id, getResponse.Attribute.Id)
	assert.Equal(t, "team", getResponse.Attribute.Key)
	assert.Equal(t, "backend", getResponse.Attribute.Value)
	assert.True(t, getResponse.Attribute.IncludeInIdToken)
	assert.False(t, getResponse.Attribute.IncludeInAccessToken)
	assert.Equal(t, testGroup.Id, getResponse.Attribute.GroupId)
}

func TestAPIGroupAttributeGet_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get non-existent attribute
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/99999"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupAttributeGet_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		attributeId    string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusMethodNotAllowed},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/" + tc.attributeId
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupAttributeGet_Unauthorized(t *testing.T) {
	// Setup: Create test group and attribute
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	attr := createTestGroupAttribute(t, testGroup.Id, "level", "senior")
	defer func() {
		_ = database.DeleteGroupAttribute(nil, attr.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.Id, 10)
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

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
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Test: Create group attribute
	createReq := api.CreateGroupAttributeRequest{
		Key:                  "location",
		Value:                "San Francisco",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
		GroupId:              testGroup.Id,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes"
	resp := makeAPIRequest(t, "POST", url, accessToken, createReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var createResponse api.CreateGroupAttributeResponse
	err := json.NewDecoder(resp.Body).Decode(&createResponse)
	assert.NoError(t, err)

	// Assert: Response should match request
	assert.Equal(t, createReq.Key, createResponse.Attribute.Key)
	assert.Equal(t, createReq.Value, createResponse.Attribute.Value)
	assert.Equal(t, createReq.IncludeInIdToken, createResponse.Attribute.IncludeInIdToken)
	assert.Equal(t, createReq.IncludeInAccessToken, createResponse.Attribute.IncludeInAccessToken)
	assert.Equal(t, createReq.GroupId, createResponse.Attribute.GroupId)
	assert.Greater(t, createResponse.Attribute.Id, int64(0))

	// Cleanup: Delete created attribute
	defer func() {
		if createResponse.Attribute.Id > 0 {
			_ = database.DeleteGroupAttribute(nil, createResponse.Attribute.Id)
		}
	}()

	// Verify attribute was created in database
	createdAttr, err := database.GetGroupAttributeById(nil, createResponse.Attribute.Id)
	assert.NoError(t, err)
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
		_ = database.DeleteGroup(nil, testGroup.Id)
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
				GroupId: testGroup.Id,
			},
			http.StatusBadRequest,
		},
		{
			"empty key",
			api.CreateGroupAttributeRequest{
				Key:     "",
				Value:   "test",
				GroupId: testGroup.Id,
			},
			http.StatusBadRequest,
		},
		{
			"value too long",
			api.CreateGroupAttributeRequest{
				Key:     "test_key",
				Value:   string(make([]byte, 251)), // 251 characters, exceeds 250 limit
				GroupId: testGroup.Id,
			},
			http.StatusBadRequest,
		},
		{
			"invalid key format",
			api.CreateGroupAttributeRequest{
				Key:     "invalid key with spaces",
				Value:   "test",
				GroupId: testGroup.Id,
			},
			http.StatusBadRequest,
		},
		{
			"group not found",
			api.CreateGroupAttributeRequest{
				Key:     "valid_key",
				Value:   "test",
				GroupId: 99999,
			},
			http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes"
			resp := makeAPIRequest(t, "POST", url, accessToken, tc.request)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupAttributeCreatePost_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes"
	req, err := http.NewRequest("POST", url, nil)
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

func TestAPIGroupAttributeCreatePost_Unauthorized(t *testing.T) {
	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes"
	req, err := http.NewRequest("POST", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

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
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create test attribute
	attr := createTestGroupAttribute(t, testGroup.Id, "status", "active")
	defer func() {
		_ = database.DeleteGroupAttribute(nil, attr.Id)
	}()

	// Test: Update attribute
	updateReq := api.UpdateGroupAttributeRequest{
		Key:                  "status",
		Value:                "inactive",
		IncludeInIdToken:     false,
		IncludeInAccessToken: true,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.Id, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateGroupAttributeResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Response should reflect updates
	assert.Equal(t, attr.Id, updateResponse.Attribute.Id)
	assert.Equal(t, updateReq.Key, updateResponse.Attribute.Key)
	assert.Equal(t, updateReq.Value, updateResponse.Attribute.Value)
	assert.Equal(t, updateReq.IncludeInIdToken, updateResponse.Attribute.IncludeInIdToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updateResponse.Attribute.IncludeInAccessToken)

	// Verify changes were persisted to database
	updatedAttr, err := database.GetGroupAttributeById(nil, attr.Id)
	assert.NoError(t, err)
	assert.NotNil(t, updatedAttr)
	assert.Equal(t, updateReq.Key, updatedAttr.Key)
	assert.Equal(t, updateReq.Value, updatedAttr.Value)
	assert.Equal(t, updateReq.IncludeInIdToken, updatedAttr.IncludeInIdToken)
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

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/99999"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupAttributeUpdatePut_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test group and attribute
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	attr := createTestGroupAttribute(t, testGroup.Id, "test_key", "test_value")
	defer func() {
		_ = database.DeleteGroupAttribute(nil, attr.Id)
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
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.Id, 10)
			resp := makeAPIRequest(t, "PUT", url, accessToken, tc.request)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupAttributeUpdatePut_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	updateReq := api.UpdateGroupAttributeRequest{
		Key:   "test_key",
		Value: "test_value",
	}

	testCases := []struct {
		name           string
		attributeId    string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusMethodNotAllowed},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/" + tc.attributeId
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer resp.Body.Close()

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
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	attr := createTestGroupAttribute(t, testGroup.Id, "test_key", "test_value")
	defer func() {
		_ = database.DeleteGroupAttribute(nil, attr.Id)
	}()

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.Id, 10)
	req, err := http.NewRequest("PUT", url, nil)
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

func TestAPIGroupAttributeUpdatePut_Unauthorized(t *testing.T) {
	// Setup: Create test group and attribute
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	attr := createTestGroupAttribute(t, testGroup.Id, "test_key", "test_value")
	defer func() {
		_ = database.DeleteGroupAttribute(nil, attr.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.Id, 10)
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

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
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	// Setup: Create test attribute
	attr := createTestGroupAttribute(t, testGroup.Id, "temp_attr", "temp_value")

	// Test: Delete attribute
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var deleteResponse api.SuccessResponse
	err := json.NewDecoder(resp.Body).Decode(&deleteResponse)
	assert.NoError(t, err)

	// Assert: Success response
	assert.True(t, deleteResponse.Success)

	// Verify attribute was actually deleted from database
	deletedAttr, err := database.GetGroupAttributeById(nil, attr.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedAttr)
}

func TestAPIGroupAttributeDelete_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Delete non-existent attribute
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/99999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIGroupAttributeDelete_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		attributeId    string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusMethodNotAllowed},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/" + tc.attributeId
			resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIGroupAttributeDelete_Unauthorized(t *testing.T) {
	// Setup: Create test group and attribute
	testGroup := createTestGroup(t)
	defer func() {
		_ = database.DeleteGroup(nil, testGroup.Id)
	}()

	attr := createTestGroupAttribute(t, testGroup.Id, "persistent", "value")
	defer func() {
		_ = database.DeleteGroupAttribute(nil, attr.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/group-attributes/" + strconv.FormatInt(attr.Id, 10)
	req, err := http.NewRequest("DELETE", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify attribute was not deleted
	stillExists, err := database.GetGroupAttributeById(nil, attr.Id)
	assert.NoError(t, err)
	assert.NotNil(t, stillExists)
}

// Helper function to create a test group attribute
func createTestGroupAttribute(t *testing.T, groupId int64, key, value string) *models.GroupAttribute {
	attr := &models.GroupAttribute{
		Key:                  key,
		Value:                value,
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
		GroupId:              groupId,
	}
	err := database.CreateGroupAttribute(nil, attr)
	assert.NoError(t, err)
	return attr
}
