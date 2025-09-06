package integrationtests

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIUserEmailPut tests the PUT /api/v1/admin/users/{id}/email endpoint
func TestAPIUserEmailPut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@email.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: false,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update user email
	updateReq := api.UpdateUserEmailRequest{
		Email:         "newemail@email.test",
		EmailVerified: true,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/email"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Email data should be updated
	assert.Equal(t, updateReq.Email, updateResponse.User.Email)
	assert.Equal(t, updateReq.EmailVerified, updateResponse.User.EmailVerified)

	// Verify changes were persisted to database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.NotNil(t, updatedUser)
	assert.Equal(t, updateReq.Email, updatedUser.Email)
	assert.Equal(t, updateReq.EmailVerified, updatedUser.EmailVerified)
	// Email verification code should be cleared when verified is true
	assert.Nil(t, updatedUser.EmailVerificationCodeEncrypted)
	assert.False(t, updatedUser.EmailVerificationCodeIssuedAt.Valid)
}

func TestAPIUserEmailPut_EmailNormalization(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@normalize.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update with email that needs normalization (uppercase, spaces)
	updateReq := api.UpdateUserEmailRequest{
		Email:         "  NORMALIZED@EMAIL.TEST  ",
		EmailVerified: false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/email"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Email should be normalized (lowercase, trimmed)
	assert.Equal(t, "normalized@email.test", updateResponse.User.Email)

	// Verify normalization in database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.Equal(t, "normalized@email.test", updatedUser.Email)
}

func TestAPIUserEmailPut_DuplicateEmail(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create first user with existing email
	existingUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "existing@duplicate.test",
		GivenName:  "Existing",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, existingUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, existingUser.Id)
	}()

	// Setup: Create second user to test duplicate email
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@duplicate.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err = database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Try to update to existing email
	updateReq := api.UpdateUserEmailRequest{
		Email:         "existing@duplicate.test",
		EmailVerified: false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/email"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return bad request due to duplicate email
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Verify original email unchanged in database
	unchangedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.Equal(t, "testuser@duplicate.test", unchangedUser.Email)
}

func TestAPIUserEmailPut_InvalidEmail(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@invalid.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	testCases := []struct {
		name  string
		email string
	}{
		{"empty email", ""},
		{"invalid format", "invalid-email"},
		{"missing domain", "user@"},
		{"missing username", "@domain.com"},
		{"multiple @", "user@@domain.com"},
		{"spaces in middle", "user @domain.com"},
		{"special chars", "user<>@domain.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			updateReq := api.UpdateUserEmailRequest{
				Email:         tc.email,
				EmailVerified: false,
			}

			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/email"
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer resp.Body.Close()

			// Assert: Should return bad request for invalid email
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestAPIUserEmailPut_SetEmailVerified(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user with unverified email and verification code
	testUser := &models.User{
		Subject:                        uuid.New(),
		Enabled:                        true,
		Email:                          "testuser@verified.test",
		GivenName:                      "Test",
		FamilyName:                     "User",
		EmailVerified:                  false,
		EmailVerificationCodeEncrypted: []byte("encrypted-verification-code"),
		EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Set email as verified
	updateReq := api.UpdateUserEmailRequest{
		Email:         "testuser@verified.test",
		EmailVerified: true,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/email"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Email should be verified
	assert.True(t, updateResponse.User.EmailVerified)

	// Verify in database that verification code was cleared
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.True(t, updatedUser.EmailVerified)
	assert.Nil(t, updatedUser.EmailVerificationCodeEncrypted)
	assert.False(t, updatedUser.EmailVerificationCodeIssuedAt.Valid)
}

func TestAPIUserEmailPut_UnsetEmailVerified(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user with verified email
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@unverified.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Unset email verification
	updateReq := api.UpdateUserEmailRequest{
		Email:         "testuser@unverified.test",
		EmailVerified: false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/email"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Email should be unverified
	assert.False(t, updateResponse.User.EmailVerified)

	// Verify in database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.False(t, updatedUser.EmailVerified)
}

func TestAPIUserEmailPut_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update email for non-existent user
	updateReq := api.UpdateUserEmailRequest{
		Email:         "test@notfound.test",
		EmailVerified: false,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/email"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Should return not found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserEmailPut_InvalidId(t *testing.T) {
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

	updateReq := api.UpdateUserEmailRequest{
		Email:         "test@invalid.test",
		EmailVerified: false,
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + tc.userId + "/email"
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)
		})
	}
}

func TestAPIUserEmailPut_InvalidRequestBody(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@invalid-body.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Invalid JSON (no body)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/email"
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

func TestAPIUserEmailPut_Unauthorized(t *testing.T) {
	// Setup: Create test user
	testUser := &models.User{
		Subject:    uuid.New(),
		Enabled:    true,
		Email:      "testuser@unauth-email.test",
		GivenName:  "Test",
		FamilyName: "User",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Request without access token
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/email"
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	// Assert: Should be unauthorized
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIUserEmailPut_PartialUpdate(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user with existing data
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "original@partial.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update only email, keep verification status
	updateReq := api.UpdateUserEmailRequest{
		Email:         "updated@partial.test",
		EmailVerified: true, // Keep verified
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/email"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer resp.Body.Close()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: Email updated, verification preserved
	assert.Equal(t, updateReq.Email, updateResponse.User.Email)
	assert.True(t, updateResponse.User.EmailVerified)

	// Verify in database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.Equal(t, updateReq.Email, updatedUser.Email)
	assert.True(t, updatedUser.EmailVerified)
}
