package integrationtests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIUserGet tests the GET /api/v1/admin/users/{id} endpoint
func TestAPIUserGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@get.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
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
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@unauth.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
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
		Email:           uniqueEmail("newuser@create.test"),
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
			_ = database.DeleteUser(context.Background(), nil, createResponse.User.Id)
		}
	}()

	// Verify user was actually created in database
	createdUser, err := database.GetUserById(context.Background(), nil, createResponse.User.Id)
	assert.NoError(t, err)
	assert.NotNil(t, createdUser)
	assert.Equal(t, createReq.Email, createdUser.Email)
}

func TestAPIUserCreatePost_DuplicateEmail(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create existing user. The duplicate is the point of this test, so
	// the address is drawn once and used twice rather than spelled twice.
	duplicateEmail := uniqueEmail("duplicate@create.test")
	existingUser := &models.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         duplicateEmail,
		GivenName:     "Existing",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, existingUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, existingUser.Id)
	}()

	// Test: Try to create user with same email
	createReq := api.CreateUserAdminRequest{
		Email:           duplicateEmail,
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
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@enabled.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
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
	updatedUser, err := database.GetUserById(context.Background(), nil, testUser.Id)
	assert.NoError(t, err)
	assert.False(t, updatedUser.Enabled)
}

func TestAPIUserEnabledPut_EnableUser(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create disabled test user
	testUser := &models.User{
		Subject:       fake.UUID(),
		Enabled:       false,
		Email:         uniqueEmail("disabled@enabled.test"),
		GivenName:     "Disabled",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
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
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@invalid.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
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
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@delete.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
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
	deletedUser, err := database.GetUserById(context.Background(), nil, testUser.Id)
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
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@delete-unauth.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
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
	stillExists, err := database.GetUserById(context.Background(), nil, testUser.Id)
	assert.NoError(t, err)
	assert.NotNil(t, stillExists)
}

// TestAPIUserCreatePost_SetPasswordTypeIsEnforced drives the published enum through the real
// endpoint, which is where it matters: openapi.yaml declares setPasswordType as enum [now, email]
// and a generated client acts on that by refusing to send anything else, so the server has to
// refuse it too or the document is narrower on paper than the endpoint is in fact.
//
// Before #350 it did not. The handler compared against the two values and refused nothing else, so
// on a deployment with SMTP configured a third value took neither arm: the account was created
// enabled and holding authserver:manage-account, with no password hash, no forgot-password code and
// no setup email, and nobody was told it existed. The first row below is that request, and it
// answered 201 then.
//
// The unit matrix in handler_api_users_crud_test.go owns the arms and what each writes. This owns
// the status through the real router, on every engine CI runs, and that no row leaves a user behind.
func TestAPIUserCreatePost_SetPasswordTypeIsEnforced(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	for _, tc := range []struct {
		name            string
		setPasswordType string
		password        string
		expectedStatus  int
	}{
		{"a third value", "later", "password123", http.StatusBadRequest},
		{"a near miss on email", "e-mail", "password123", http.StatusBadRequest},
		{"the right word in the wrong case", "Email", "password123", http.StatusBadRequest},
		// Absent is permitted by the schema and means "now", so it is accepted with a password
		// and refused without one. It is refused here for the missing password, not for the
		// missing field, which is the distinction the default exists to make.
		{"absent with a password", "", "password123", http.StatusCreated},
		{"absent without a password", "", "", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email := uniqueEmail("setpasswordtype@create.test")
			req := api.CreateUserAdminRequest{
				Email:           email,
				GivenName:       "Set",
				FamilyName:      "Password",
				SetPasswordType: tc.setPasswordType,
				Password:        tc.password,
			}

			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/create"
			resp := makeAPIRequest(t, "POST", url, accessToken, req)
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, tc.expectedStatus, resp.StatusCode)

			if tc.expectedStatus != http.StatusCreated {
				// A refusal must leave nothing behind. The defect's whole harm was a row created
				// where the caller was told nothing, so a 400 that still wrote one would be the
				// same failure wearing a different status.
				user, err := database.GetUserByEmail(context.Background(), nil, email)
				require.NoError(t, err)
				assert.Nil(t, user, "a refused create must not have written a user row")
			}
		})
	}
}
