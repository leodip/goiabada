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

// Helper function to create a test user attribute
func createTestUserAttribute(t *testing.T, userId int64, key, value string) *models.UserAttribute {
	attr := &models.UserAttribute{
		Key:                  key,
		Value:                value,
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
		UserId:               userId,
	}
	err := database.CreateUserAttribute(nil, attr)
	assert.NoError(t, err)
	return attr
}

// TestAPIUserAttributesGet tests the GET /api/v1/admin/users/{id}/attributes endpoint
func TestAPIUserAttributesGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@attributes.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test attributes
	attr1 := createTestUserAttribute(t, testUser.Id, "department", "engineering")
	attr2 := createTestUserAttribute(t, testUser.Id, "role", "developer")
	defer func() {
		_ = database.DeleteUserAttribute(nil, attr1.Id)
		_ = database.DeleteUserAttribute(nil, attr2.Id)
	}()

	// Test: Get user attributes
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetUserAttributesResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return both attributes
	assert.Len(t, getResponse.Attributes, 2)
	
	// Create a map for easier assertion
	attrMap := make(map[string]api.UserAttributeResponse)
	for _, attr := range getResponse.Attributes {
		attrMap[attr.Key] = attr
	}

	// Verify both attributes are present
	deptAttr, exists := attrMap["department"]
	assert.True(t, exists)
	assert.Equal(t, "engineering", deptAttr.Value)
	assert.True(t, deptAttr.IncludeInIdToken)
	assert.False(t, deptAttr.IncludeInAccessToken)
	assert.Equal(t, testUser.Id, deptAttr.UserId)

	roleAttr, exists := attrMap["role"]
	assert.True(t, exists)
	assert.Equal(t, "developer", roleAttr.Value)
}

func TestAPIUserAttributesGet_EmptyAttributes(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without attributes
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@empty-attrs.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Get user attributes for user with no attributes
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetUserAttributesResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return empty attributes array
	assert.Len(t, getResponse.Attributes, 0)
}

func TestAPIUserAttributesGet_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get attributes for non-existent user
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserAttributesGet_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		userId         string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusBadRequest},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.userId + "/attributes"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributesGet_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth-attrs.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/attributes"
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserAttributeGet tests the GET /api/v1/admin/user-attributes/{id} endpoint
func TestAPIUserAttributeGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@attr-get.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test attribute
	attr := createTestUserAttribute(t, testUser.Id, "team", "backend")
	defer func() {
		_ = database.DeleteUserAttribute(nil, attr.Id)
	}()

	// Test: Get specific user attribute
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.Id, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetUserAttributeResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	assert.NoError(t, err)

	// Assert: Should return the correct attribute
	assert.Equal(t, attr.Id, getResponse.Attribute.Id)
	assert.Equal(t, "team", getResponse.Attribute.Key)
	assert.Equal(t, "backend", getResponse.Attribute.Value)
	assert.True(t, getResponse.Attribute.IncludeInIdToken)
	assert.False(t, getResponse.Attribute.IncludeInAccessToken)
	assert.Equal(t, testUser.Id, getResponse.Attribute.UserId)
}

func TestAPIUserAttributeGet_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get non-existent attribute
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/99999"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserAttributeGet_InvalidId(t *testing.T) {
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
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/" + tc.attributeId
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributeGet_Unauthorized(t *testing.T) {
	// Setup: Create test user and attribute
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth-attr.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	attr := createTestUserAttribute(t, testUser.Id, "level", "senior")
	defer func() {
		_ = database.DeleteUserAttribute(nil, attr.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.Id, 10)
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserAttributeCreatePost tests the POST /api/v1/admin/user-attributes endpoint
func TestAPIUserAttributeCreatePost_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@attr-create.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Create user attribute
	createReq := api.CreateUserAttributeRequest{
		Key:                  "location",
		Value:                "San Francisco",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
		UserId:               testUser.Id,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes"
	resp := makeAPIRequest(t, "POST", url, accessToken, createReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var createResponse api.CreateUserAttributeResponse
	err = json.NewDecoder(resp.Body).Decode(&createResponse)
	assert.NoError(t, err)

	// Assert: Response should match request
	assert.Equal(t, createReq.Key, createResponse.Attribute.Key)
	assert.Equal(t, createReq.Value, createResponse.Attribute.Value)
	assert.Equal(t, createReq.IncludeInIdToken, createResponse.Attribute.IncludeInIdToken)
	assert.Equal(t, createReq.IncludeInAccessToken, createResponse.Attribute.IncludeInAccessToken)
	assert.Equal(t, createReq.UserId, createResponse.Attribute.UserId)
	assert.Greater(t, createResponse.Attribute.Id, int64(0))

	// Cleanup: Delete created attribute
	defer func() {
		if createResponse.Attribute.Id > 0 {
			_ = database.DeleteUserAttribute(nil, createResponse.Attribute.Id)
		}
	}()

	// Verify attribute was created in database
	createdAttr, err := database.GetUserAttributeById(nil, createResponse.Attribute.Id)
	assert.NoError(t, err)
	assert.NotNil(t, createdAttr)
	assert.Equal(t, createReq.Key, createdAttr.Key)
	assert.Equal(t, createReq.Value, createdAttr.Value)
}

func TestAPIUserAttributeCreatePost_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@attr-validation.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	testCases := []struct {
		name           string
		request        api.CreateUserAttributeRequest
		expectedStatus int
	}{
		{
			"missing key",
			api.CreateUserAttributeRequest{
				Value:  "test",
				UserId: testUser.Id,
			},
			http.StatusBadRequest,
		},
		{
			"empty key",
			api.CreateUserAttributeRequest{
				Key:    "",
				Value:  "test",
				UserId: testUser.Id,
			},
			http.StatusBadRequest,
		},
		{
			"value too long",
			api.CreateUserAttributeRequest{
				Key:    "test_key",
				Value:  string(make([]byte, 251)), // 251 characters, exceeds 250 limit
				UserId: testUser.Id,
			},
			http.StatusBadRequest,
		},
		{
			"invalid key format",
			api.CreateUserAttributeRequest{
				Key:    "invalid key with spaces",
				Value:  "test",
				UserId: testUser.Id,
			},
			http.StatusBadRequest,
		},
		{
			"user not found",
			api.CreateUserAttributeRequest{
				Key:    "valid_key",
				Value:  "test",
				UserId: 99999,
			},
			http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes"
			resp := makeAPIRequest(t, "POST", url, accessToken, tc.request)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributeCreatePost_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes"
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

func TestAPIUserAttributeCreatePost_Unauthorized(t *testing.T) {
	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes"
	req, err := http.NewRequest("POST", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserAttributeUpdatePut tests the PUT /api/v1/admin/user-attributes/{id} endpoint
func TestAPIUserAttributeUpdatePut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@attr-update.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test attribute
	attr := createTestUserAttribute(t, testUser.Id, "status", "active")
	defer func() {
		_ = database.DeleteUserAttribute(nil, attr.Id)
	}()

	// Test: Update attribute
	updateReq := api.UpdateUserAttributeRequest{
		Key:                  "status",
		Value:                "inactive",
		IncludeInIdToken:     false,
		IncludeInAccessToken: true,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.Id, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.GetUserAttributeResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Response should reflect updates
	assert.Equal(t, attr.Id, updateResponse.Attribute.Id)
	assert.Equal(t, updateReq.Key, updateResponse.Attribute.Key)
	assert.Equal(t, updateReq.Value, updateResponse.Attribute.Value)
	assert.Equal(t, updateReq.IncludeInIdToken, updateResponse.Attribute.IncludeInIdToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updateResponse.Attribute.IncludeInAccessToken)

	// Verify changes were persisted to database
	updatedAttr, err := database.GetUserAttributeById(nil, attr.Id)
	assert.NoError(t, err)
	assert.NotNil(t, updatedAttr)
	assert.Equal(t, updateReq.Key, updatedAttr.Key)
	assert.Equal(t, updateReq.Value, updatedAttr.Value)
	assert.Equal(t, updateReq.IncludeInIdToken, updatedAttr.IncludeInIdToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updatedAttr.IncludeInAccessToken)
}

func TestAPIUserAttributeUpdatePut_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update non-existent attribute
	updateReq := api.UpdateUserAttributeRequest{
		Key:   "test_key",
		Value: "test_value",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/99999"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserAttributeUpdatePut_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user and attribute
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@attr-update-validation.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	attr := createTestUserAttribute(t, testUser.Id, "test_key", "test_value")
	defer func() {
		_ = database.DeleteUserAttribute(nil, attr.Id)
	}()

	testCases := []struct {
		name           string
		request        api.UpdateUserAttributeRequest
		expectedStatus int
	}{
		{
			"missing key",
			api.UpdateUserAttributeRequest{
				Value: "test",
			},
			http.StatusBadRequest,
		},
		{
			"empty key",
			api.UpdateUserAttributeRequest{
				Key:   "",
				Value: "test",
			},
			http.StatusBadRequest,
		},
		{
			"value too long",
			api.UpdateUserAttributeRequest{
				Key:   "valid_key",
				Value: string(make([]byte, 251)), // 251 characters
			},
			http.StatusBadRequest,
		},
		{
			"invalid key format",
			api.UpdateUserAttributeRequest{
				Key:   "invalid key with spaces",
				Value: "test",
			},
			http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.Id, 10)
			resp := makeAPIRequest(t, "PUT", url, accessToken, tc.request)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributeUpdatePut_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	updateReq := api.UpdateUserAttributeRequest{
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
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/" + tc.attributeId
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributeUpdatePut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user and attribute
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@attr-invalid-body.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	attr := createTestUserAttribute(t, testUser.Id, "test_key", "test_value")
	defer func() {
		_ = database.DeleteUserAttribute(nil, attr.Id)
	}()

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.Id, 10)
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

func TestAPIUserAttributeUpdatePut_Unauthorized(t *testing.T) {
	// Setup: Create test user and attribute
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@attr-unauth-update.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	attr := createTestUserAttribute(t, testUser.Id, "test_key", "test_value")
	defer func() {
		_ = database.DeleteUserAttribute(nil, attr.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.Id, 10)
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserAttributeDelete tests the DELETE /api/v1/admin/user-attributes/{id} endpoint
func TestAPIUserAttributeDelete_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@attr-delete.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test attribute
	attr := createTestUserAttribute(t, testUser.Id, "temp_attr", "temp_value")

	// Test: Delete attribute
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var deleteResponse api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&deleteResponse)
	assert.NoError(t, err)

	// Assert: Success response
	assert.True(t, deleteResponse.Success)

	// Verify attribute was actually deleted from database
	deletedAttr, err := database.GetUserAttributeById(nil, attr.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedAttr)
}

func TestAPIUserAttributeDelete_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Delete non-existent attribute
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/99999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer resp.Body.Close()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserAttributeDelete_InvalidId(t *testing.T) {
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
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/" + tc.attributeId
			resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributeDelete_Unauthorized(t *testing.T) {
	// Setup: Create test user and attribute
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@attr-delete-unauth.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	attr := createTestUserAttribute(t, testUser.Id, "persistent", "value")
	defer func() {
		_ = database.DeleteUserAttribute(nil, attr.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.Id, 10)
	req, err := http.NewRequest("DELETE", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify attribute was not deleted
	stillExists, err := database.GetUserAttributeById(nil, attr.Id)
	assert.NoError(t, err)
	assert.NotNil(t, stillExists)
}