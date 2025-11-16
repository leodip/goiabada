package integrationtests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIUserGet tests the GET /api/v1/admin/users/{id} endpoint
func TestAPIUserGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@get.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Get user by ID
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getUserResponse api.GetUserResponse
	err = json.NewDecoder(resp.Body).Decode(&getUserResponse)
	assert.NoError(t, err)

	// Assert: User data should match
	assert.Equal(t, testUser.Email, getUserResponse.User.Email)
	assert.Equal(t, testUser.GivenName, getUserResponse.User.GivenName)
	assert.Equal(t, testUser.FamilyName, getUserResponse.User.FamilyName)
	assert.Equal(t, testUser.Enabled, getUserResponse.User.Enabled)
	assert.Equal(t, testUser.EmailVerified, getUserResponse.User.EmailVerified)
}

func TestAPIUserGet_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get non-existent user
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserGet_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		userId         string
		expectedStatus int
	}{
		{"non-numeric ID", "abc", http.StatusBadRequest},
		{"empty ID", "", http.StatusNotFound},      // Empty ID routes to different endpoint
		{"negative ID", "-1", http.StatusNotFound}, // -1 is valid int, but user doesn't exist
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.userId
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			// Assert: Should return expected status
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserGet_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@unauth.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10)
	req, err := http.NewRequest("GET", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserCreatePost tests the POST /api/v1/admin/users/create endpoint
func TestAPIUserCreatePost_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Create user with password (using simple password that meets PasswordPolicyLow - at least 6 chars)
	createReq := api.CreateUserAdminRequest{
		Email:           "newuser@create.test",
		GivenName:       "New",
		FamilyName:      "User",
		EmailVerified:   true,
		SetPasswordType: "now",
		Password:        "password123",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/create"
	resp := makeAPIRequest(t, "POST", url, accessToken, createReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var createResponse api.CreateUserResponse
	err := json.NewDecoder(resp.Body).Decode(&createResponse)
	assert.NoError(t, err)

	// Check for successful creation first
	if resp.StatusCode != http.StatusCreated {
		// Read and print response body for debugging
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Logf("Status: %d, Response body: %s", resp.StatusCode, string(body))
		t.FailNow()
	}

	// Assert: User data should match
	assert.Equal(t, createReq.Email, createResponse.User.Email)
	assert.Equal(t, createReq.GivenName, createResponse.User.GivenName)
	assert.Equal(t, createReq.FamilyName, createResponse.User.FamilyName)
	assert.Equal(t, createReq.EmailVerified, createResponse.User.EmailVerified)
	assert.True(t, createResponse.User.Enabled)

	// Cleanup: Delete created user
	defer func() {
		if createResponse.User.Id > 0 {
			_ = database.DeleteUser(nil, createResponse.User.Id)
		}
	}()

	// Verify user was actually created in database
	createdUser, err := database.GetUserById(nil, createResponse.User.Id)
	assert.NoError(t, err)
	assert.NotNil(t, createdUser)
	assert.Equal(t, createReq.Email, createdUser.Email)
}

func TestAPIUserCreatePost_DuplicateEmail(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create existing user
	existingUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "duplicate@create.test",
		GivenName:     "Existing",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, existingUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, existingUser.Id)
	}()

	// Test: Try to create user with same email
	createReq := api.CreateUserAdminRequest{
		Email:           "duplicate@create.test",
		GivenName:       "New",
		FamilyName:      "User",
		EmailVerified:   true,
		SetPasswordType: "now",
		Password:        "password123",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/create"
	resp := makeAPIRequest(t, "POST", url, accessToken, createReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return conflict
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestAPIUserCreatePost_ValidationErrors(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		name           string
		request        api.CreateUserAdminRequest
		expectedStatus int
	}{
		{
			"missing email",
			api.CreateUserAdminRequest{
				GivenName:       "Test",
				FamilyName:      "User",
				SetPasswordType: "now",
				Password:        "password123",
			},
			http.StatusBadRequest,
		},
		{
			"invalid email format",
			api.CreateUserAdminRequest{
				Email:           "invalid-email",
				GivenName:       "Test",
				FamilyName:      "User",
				SetPasswordType: "now",
				Password:        "password123",
			},
			http.StatusBadRequest,
		},
		{
			"email too long",
			api.CreateUserAdminRequest{
				Email:           "verylongemailaddressthatexceedsthemaximumlengthof60chars@test.com",
				GivenName:       "Test",
				FamilyName:      "User",
				SetPasswordType: "now",
				Password:        "password123",
			},
			http.StatusBadRequest,
		},
		{
			"missing password when required",
			api.CreateUserAdminRequest{
				Email:           "test@validation.test",
				GivenName:       "Test",
				FamilyName:      "User",
				SetPasswordType: "now",
			},
			http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/create"
			resp := makeAPIRequest(t, "POST", url, accessToken, tc.request)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserCreatePost_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/create"
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte("invalid json")))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserCreatePost_Unauthorized(t *testing.T) {
	// Test: Request without access token
	createReq := api.CreateUserAdminRequest{
		Email:           "unauthorized@create.test",
		GivenName:       "Test",
		FamilyName:      "User",
		SetPasswordType: "now",
		Password:        "password123",
	}

	reqBody, err := json.Marshal(createReq)
	assert.NoError(t, err)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/create"
	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestAPIUserEnabledPut tests the PUT /api/v1/admin/users/{id}/enabled endpoint
func TestAPIUserEnabledPut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user (enabled by default)
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@enabled.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Disable user
	updateReq := api.UpdateUserEnabledRequest{
		Enabled: false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/enabled"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: User should now be disabled
	assert.False(t, updateResponse.User.Enabled)
	assert.Equal(t, testUser.Email, updateResponse.User.Email)

	// Verify in database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.False(t, updatedUser.Enabled)
}

func TestAPIUserEnabledPut_EnableUser(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create disabled test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       false,
		Email:         "disabled@enabled.test",
		GivenName:     "Disabled",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Enable user
	updateReq := api.UpdateUserEnabledRequest{
		Enabled: true,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/enabled"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: User should now be enabled
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, updateResponse.User.Enabled)
}

func TestAPIUserEnabledPut_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update non-existent user
	updateReq := api.UpdateUserEnabledRequest{
		Enabled: false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/enabled"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserEnabledPut_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Invalid user ID
	updateReq := api.UpdateUserEnabledRequest{
		Enabled: false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/invalid/enabled"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserEnabledPut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@invalid.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Invalid JSON
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/enabled"
	req, err := http.NewRequest("PUT", url, bytes.NewReader([]byte("invalid json")))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestAPIUserDelete tests the DELETE /api/v1/admin/users/{id} endpoint
func TestAPIUserDelete_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@delete.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)

	// Test: Delete user
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var deleteResponse api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&deleteResponse)
	assert.NoError(t, err)

	// Assert: Success response
	assert.True(t, deleteResponse.Success)

	// Verify user was actually deleted from database
	deletedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.Nil(t, deletedUser)
}

func TestAPIUserDelete_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Delete non-existent user
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return 404
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserDelete_InvalidId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	testCases := []struct {
		id             string
		expectedStatus int
	}{
		{"invalid", http.StatusBadRequest},
		{"abc", http.StatusBadRequest},
		{"-1", http.StatusNotFound}, // -1 is valid int, user doesn't exist
	}

	for _, tc := range testCases {
		t.Run("invalid ID: "+tc.id, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.id
			resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			// Assert: Should return expected status
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserDelete_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@delete-unauth.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10)
	req, err := http.NewRequest("DELETE", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Verify user was not deleted
	stillExists, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.NotNil(t, stillExists)
}
