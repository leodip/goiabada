package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIUserAttributesGet tests the GET /api/v1/admin/users/{id}/attributes endpoint
func TestAPIUserAttributesGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@attributes.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test attributes
	attr1 := createTestUserAttribute(t, testUser.ID, "department", "engineering")
	attr2 := createTestUserAttribute(t, testUser.ID, "role", "developer")
	defer func() {
		_ = database.DeleteUserAttribute(context.Background(), nil, attr1.ID)
		_ = database.DeleteUserAttribute(context.Background(), nil, attr2.ID)
	}()

	// Test: Get user attributes
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetUserAttributesResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

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
	assert.True(t, deptAttr.IncludeInIDToken)
	assert.False(t, deptAttr.IncludeInAccessToken)
	assert.Equal(t, testUser.ID, deptAttr.UserID)

	roleAttr, exists := attrMap["role"]
	assert.True(t, exists)
	assert.Equal(t, "developer", roleAttr.Value)
}

func TestAPIUserAttributesGet_EmptyAttributes(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without attributes
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@empty-attrs.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Get user attributes for user with no attributes
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var getResponse api.GetUserAttributesResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: Should return empty attributes array
	assert.Empty(t, getResponse.Attributes)
}

func TestAPIUserAttributesGet_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get attributes for non-existent user
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/99999/attributes"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserAttributesGet_InvalidID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		userID         string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		// An empty segment matches no route, so the group answers 404 (#462 decision 4).
		{"empty ID", "", http.StatusNotFound},
		{"negative ID", "-1", http.StatusNotFound},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + tc.userID + "/attributes"
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributesGet_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@unauth-attrs.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.ID, 10) + "/attributes"
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserAttributeGet tests the GET /api/v1/admin/user-attributes/{id} endpoint
func TestAPIUserAttributeGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@attr-get.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test attribute
	attr := createTestUserAttribute(t, testUser.ID, "team", "backend")
	defer func() {
		_ = database.DeleteUserAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Get specific user attribute
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.ID, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getResponse api.GetUserAttributeResponse
	err = json.NewDecoder(resp.Body).Decode(&getResponse)
	require.NoError(t, err)

	// Assert: Should return the correct attribute
	assert.Equal(t, attr.ID, getResponse.Attribute.ID)
	assert.Equal(t, "team", getResponse.Attribute.Key)
	assert.Equal(t, "backend", getResponse.Attribute.Value)
	assert.True(t, getResponse.Attribute.IncludeInIDToken)
	assert.False(t, getResponse.Attribute.IncludeInAccessToken)
	assert.Equal(t, testUser.ID, getResponse.Attribute.UserID)
}

func TestAPIUserAttributeGet_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get non-existent attribute
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/99999"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserAttributeGet_InvalidID(t *testing.T) {
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
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/" + tc.attributeID
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributeGet_Unauthorized(t *testing.T) {
	// Setup: Create test user and attribute
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@unauth-attr.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	attr := createTestUserAttribute(t, testUser.ID, "level", "senior")
	defer func() {
		_ = database.DeleteUserAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.ID, 10)
	req, err := http.NewRequest("GET", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserAttributeCreatePost tests the POST /api/v1/admin/user-attributes endpoint
func TestAPIUserAttributeCreatePost_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@attr-create.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Test: Create user attribute
	createReq := api.CreateUserAttributeRequest{
		Key:                  "location",
		Value:                "San Francisco",
		IncludeInIDToken:     true,
		IncludeInAccessToken: true,
		UserID:               testUser.ID,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes"
	resp := makeAPIRequest(t, "POST", url, accessToken, createReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var createResponse api.CreateUserAttributeResponse
	err = json.NewDecoder(resp.Body).Decode(&createResponse)
	require.NoError(t, err)

	// Assert: Response should match request
	assert.Equal(t, createReq.Key, createResponse.Attribute.Key)
	assert.Equal(t, createReq.Value, createResponse.Attribute.Value)
	assert.Equal(t, createReq.IncludeInIDToken, createResponse.Attribute.IncludeInIDToken)
	assert.Equal(t, createReq.IncludeInAccessToken, createResponse.Attribute.IncludeInAccessToken)
	assert.Equal(t, createReq.UserID, createResponse.Attribute.UserID)
	assert.Positive(t, createResponse.Attribute.ID)

	// Cleanup: Delete created attribute
	defer func() {
		if createResponse.Attribute.ID > 0 {
			_ = database.DeleteUserAttribute(context.Background(), nil, createResponse.Attribute.ID)
		}
	}()

	// Verify attribute was created in database
	createdAttr, err := database.GetUserAttributeByID(context.Background(), nil, createResponse.Attribute.ID)
	require.NoError(t, err)
	assert.NotNil(t, createdAttr)
	assert.Equal(t, createReq.Key, createdAttr.Key)
	assert.Equal(t, createReq.Value, createdAttr.Value)
}

func TestAPIUserAttributeCreatePost_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@attr-validation.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
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
				UserID: testUser.ID,
			},
			http.StatusBadRequest,
		},
		{
			"empty key",
			api.CreateUserAttributeRequest{
				Key:    "",
				Value:  "test",
				UserID: testUser.ID,
			},
			http.StatusBadRequest,
		},
		{
			"value too long",
			api.CreateUserAttributeRequest{
				Key:    "test_key",
				Value:  string(make([]byte, 251)), // 251 characters, exceeds 250 limit
				UserID: testUser.ID,
			},
			http.StatusBadRequest,
		},
		{
			"invalid key format",
			api.CreateUserAttributeRequest{
				Key:    "invalid key with spaces",
				Value:  "test",
				UserID: testUser.ID,
			},
			http.StatusBadRequest,
		},
		{
			"user not found",
			api.CreateUserAttributeRequest{
				Key:    "valid_key",
				Value:  "test",
				UserID: 99999,
			},
			http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes"
			resp := makeAPIRequest(t, "POST", url, accessToken, tc.request)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributeCreatePost_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Invalid JSON
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes"
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

func TestAPIUserAttributeCreatePost_Unauthorized(t *testing.T) {
	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes"
	req, err := http.NewRequest("POST", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserAttributeUpdatePut tests the PUT /api/v1/admin/user-attributes/{id} endpoint
func TestAPIUserAttributeUpdatePut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@attr-update.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test attribute
	attr := createTestUserAttribute(t, testUser.ID, "status", "active")
	defer func() {
		_ = database.DeleteUserAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Update attribute
	updateReq := api.UpdateUserAttributeRequest{
		Key:                  "status",
		Value:                "inactive",
		IncludeInIDToken:     false,
		IncludeInAccessToken: true,
	}

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.ID, 10)
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.GetUserAttributeResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)

	// Assert: Response should reflect updates
	assert.Equal(t, attr.ID, updateResponse.Attribute.ID)
	assert.Equal(t, updateReq.Key, updateResponse.Attribute.Key)
	assert.Equal(t, updateReq.Value, updateResponse.Attribute.Value)
	assert.Equal(t, updateReq.IncludeInIDToken, updateResponse.Attribute.IncludeInIDToken)
	assert.Equal(t, updateReq.IncludeInAccessToken, updateResponse.Attribute.IncludeInAccessToken)

	// Verify changes were persisted to database
	updatedAttr, err := database.GetUserAttributeByID(context.Background(), nil, attr.ID)
	require.NoError(t, err)
	assert.NotNil(t, updatedAttr)
	assert.Equal(t, updateReq.Key, updatedAttr.Key)
	assert.Equal(t, updateReq.Value, updatedAttr.Value)
	assert.Equal(t, updateReq.IncludeInIDToken, updatedAttr.IncludeInIDToken)
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

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/99999"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserAttributeUpdatePut_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user and attribute
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@attr-update-validation.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	attr := createTestUserAttribute(t, testUser.ID, "test_key", "test_value")
	defer func() {
		_ = database.DeleteUserAttribute(context.Background(), nil, attr.ID)
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
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.ID, 10)
			resp := makeAPIRequest(t, "PUT", url, accessToken, tc.request)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributeUpdatePut_InvalidID(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	updateReq := api.UpdateUserAttributeRequest{
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
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/" + tc.attributeID
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributeUpdatePut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user and attribute
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@attr-invalid-body.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	attr := createTestUserAttribute(t, testUser.ID, "test_key", "test_value")
	defer func() {
		_ = database.DeleteUserAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Invalid JSON
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.ID, 10)
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

func TestAPIUserAttributeUpdatePut_Unauthorized(t *testing.T) {
	// Setup: Create test user and attribute
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@attr-unauth-update.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	attr := createTestUserAttribute(t, testUser.ID, "test_key", "test_value")
	defer func() {
		_ = database.DeleteUserAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.ID, 10)
	req, err := http.NewRequest("PUT", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserAttributeDelete tests the DELETE /api/v1/admin/user-attributes/{id} endpoint
func TestAPIUserAttributeDelete_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@attr-delete.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	// Setup: Create test attribute
	attr := createTestUserAttribute(t, testUser.ID, "temp_attr", "temp_value")

	// Test: Delete attribute
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.ID, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var deleteResponse api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&deleteResponse)
	require.NoError(t, err)

	// Assert: Success response
	assert.True(t, deleteResponse.Success)

	// Verify attribute was actually deleted from database
	deletedAttr, err := database.GetUserAttributeByID(context.Background(), nil, attr.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedAttr)
}

func TestAPIUserAttributeDelete_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Delete non-existent attribute
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/99999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserAttributeDelete_InvalidID(t *testing.T) {
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
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/" + tc.attributeID
			resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserAttributeDelete_Unauthorized(t *testing.T) {
	// Setup: Create test user and attribute
	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@attr-delete-unauth.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.ID)
	}()

	attr := createTestUserAttribute(t, testUser.ID, "persistent", "value")
	defer func() {
		_ = database.DeleteUserAttribute(context.Background(), nil, attr.ID)
	}()

	// Test: Request without access token
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes/" + strconv.FormatInt(attr.ID, 10)
	req, err := http.NewRequest("DELETE", url, nil)
	require.NoError(t, err)

	httpClient := createHTTPClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify attribute was not deleted
	stillExists, err := database.GetUserAttributeByID(context.Background(), nil, attr.ID)
	require.NoError(t, err)
	assert.NotNil(t, stillExists)
}

// Helper function to create a test user attribute
func createTestUserAttribute(t *testing.T, userID int64, key, value string) *record.UserAttribute {
	attr := &record.UserAttribute{
		Key:                  key,
		Value:                value,
		IncludeInIDToken:     true,
		IncludeInAccessToken: false,
		UserID:               userID,
	}
	err := database.CreateUserAttribute(context.Background(), nil, attr)
	assert.NoError(t, err)
	return attr
}

// TestAPIUserAttribute_AngleBracketsRejected pins the reject on both wiring points, create and
// update: each carries its own check (#275).
func TestAPIUserAttribute_AngleBracketsRejected(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@attr-angle.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() { _ = database.DeleteUser(context.Background(), nil, testUser.ID) }()

	attr := createTestUserAttribute(t, testUser.ID, "status", "active")
	defer func() { _ = database.DeleteUserAttribute(context.Background(), nil, attr.ID) }()

	base := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-attributes"

	t.Run("create", func(t *testing.T) {
		resp := makeAPIRequest(t, "POST", base, accessToken, api.CreateUserAttributeRequest{
			Key:    "location",
			Value:  "<b>San Francisco</b>",
			UserID: testUser.ID,
		})
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		var errResp api.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		assert.Equal(t, "validator.attribute.value_angle_brackets", errResp.ErrorCode)
	})

	t.Run("update", func(t *testing.T) {
		resp := makeAPIRequest(t, "PUT", base+"/"+strconv.FormatInt(attr.ID, 10), accessToken,
			api.UpdateUserAttributeRequest{Key: "status", Value: "a < b"})
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		var errResp api.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		assert.Equal(t, "validator.attribute.value_angle_brackets", errResp.ErrorCode)

		stored, err := database.GetUserAttributeByID(context.Background(), nil, attr.ID)
		require.NoError(t, err)
		assert.Equal(t, "active", stored.Value)
	})
}

// TestAPIUserAttribute_AmpersandsAndQuotesStoredVerbatim is the accepted twin, on both wiring
// points like its rejected counterpart above: create and update assign the value independently, so
// a rewrite installed on one of them is invisible to a test that only exercises the other.
// Attribute values are not trimmed, so the surrounding spaces come back too.
func TestAPIUserAttribute_AmpersandsAndQuotesStoredVerbatim(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	testUser := &record.User{
		Subject:    fake.UUID(),
		Enabled:    true,
		Email:      uniqueEmail("testuser@attr-verbatim.test"),
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() { _ = database.DeleteUser(context.Background(), nil, testUser.ID) }()

	value := `  Tom & Jerry said "hi"  `
	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/admin/user-attributes",
		accessToken, api.CreateUserAttributeRequest{Key: "motto", Value: value, UserID: testUser.ID})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var createResponse api.CreateUserAttributeResponse
	err = json.NewDecoder(resp.Body).Decode(&createResponse)
	require.NoError(t, err)
	assert.Equal(t, value, createResponse.Attribute.Value)

	stored, err := database.GetUserAttributeByID(context.Background(), nil, createResponse.Attribute.ID)
	require.NoError(t, err)
	assert.Equal(t, value, stored.Value)
	defer func() { _ = database.DeleteUserAttribute(context.Background(), nil, createResponse.Attribute.ID) }()

	updated := `  AT&T said "again"  `
	updateResp := makeAPIRequest(t, "PUT", appConfig.AuthServer.BaseURL+"/api/v1/admin/user-attributes/"+
		strconv.FormatInt(createResponse.Attribute.ID, 10), accessToken,
		api.UpdateUserAttributeRequest{Key: "motto", Value: updated})
	defer func() { _ = updateResp.Body.Close() }()

	assert.Equal(t, http.StatusOK, updateResp.StatusCode)

	var updateResponse api.GetUserAttributeResponse
	err = json.NewDecoder(updateResp.Body).Decode(&updateResponse)
	require.NoError(t, err)
	assert.Equal(t, updated, updateResponse.Attribute.Value)

	stored, err = database.GetUserAttributeByID(context.Background(), nil, createResponse.Attribute.ID)
	require.NoError(t, err)
	assert.Equal(t, updated, stored.Value)
}
