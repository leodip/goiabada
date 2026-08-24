package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// TestAPIUserPasswordPut tests the PUT /api/v1/admin/users/{id}/password endpoint
func TestAPIUserPasswordPut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@password.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
		PasswordHash:  "old-password-hash",
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Update password
	updateReq := api.UpdateUserPasswordRequest{
		NewPassword: "newSecurePassword123!",
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/password"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: User ID should match
	assert.Equal(t, testUser.Id, updateResponse.User.Id)

	// Verify password was actually updated in database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.NotEqual(t, "old-password-hash", updatedUser.PasswordHash)

	// Verify new password can be validated
	assert.True(t, hashutil.VerifyPasswordHash(updatedUser.PasswordHash, updateReq.NewPassword))
}

func TestAPIUserPasswordPut_ValidationError(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@password-validation.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	testCases := []struct {
		name     string
		password string
	}{
		{"empty password", ""},
		{"too short password", "123"},
		{"too long password", strings.Repeat("a", 65)}, // Over 64 char limit
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			updateReq := api.UpdateUserPasswordRequest{
				NewPassword: tc.password,
			}
			url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/password"
			resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
			defer func() { _ = resp.Body.Close() }()

			// Assert: Should return bad request
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestAPIUserPasswordPut_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update password for non-existent user
	updateReq := api.UpdateUserPasswordRequest{
		NewPassword: "newSecurePassword123!",
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/password"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return not found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserPasswordPut_InvalidUserId(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Update password with invalid user ID
	updateReq := api.UpdateUserPasswordRequest{
		NewPassword: "newSecurePassword123!",
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/invalid/password"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return bad request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestAPIUserOTPPut tests the PUT /api/v1/admin/users/{id}/otp endpoint
func TestAPIUserOTPPut_DisableSuccess(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user with OTP enabled
	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "test",
		AccountName: "testuser@otp.test",
	})
	assert.NoError(t, err)

	testUser := &models.User{
		Subject:            uuid.New(),
		Enabled:            true,
		Email:              "testuser@otp.test",
		GivenName:          "Test",
		FamilyName:         "User",
		EmailVerified:      true,
		OTPEnabled:         true,
		OTPSecret:          secret.Secret(),
		OTPSecretEncrypted: encryptOTPSecretForTest(t, secret.Secret()),
	}
	err = database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Disable OTP
	updateReq := api.UpdateUserOTPRequest{
		Enabled: false,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	assert.NoError(t, err)

	// Assert: User ID should match and OTP should be disabled
	assert.Equal(t, testUser.Id, updateResponse.User.Id)
	assert.False(t, updateResponse.User.OTPEnabled)

	// Verify OTP was actually disabled in database
	updatedUser, err := database.GetUserById(nil, testUser.Id)
	assert.NoError(t, err)
	assert.False(t, updatedUser.OTPEnabled)
	assert.Empty(t, updatedUser.OTPSecret)
}

// TestAPIUserOTPPut_DisableResetsConsumedStep pins the second of the two disable sites #111
// decision 4 names: an admin disabling a user's OTP returns their consumed-step marker to 0, just
// as the self-service disable does. Forgetting the reset in this handler left the complete suite
// green before this case existed, because seam 4 only ever exercised the account endpoint.
//
// A new function rather than an extension of TestAPIUserOTPPut_DisableSuccess above, which owns the
// admin response shape and holds no account token: this one needs a user who can drive
// PUT /api/v1/account/otp themselves, since enrolling is the only endpoint-observable way to
// consume a step and the only way to see afterwards that it was released.
//
// **Keep this case**, for the same reason seam 4's does: it asserts one code accepted twice, which
// reads like the replay #111 refuses. See TestAPIAccountOTPPut_Disable_ResetsConsumedStep.
func TestAPIUserOTPPut_DisableResetsConsumedStep(t *testing.T) {
	accessToken, user := getUserAccessTokenWithAccountScope(t)
	setUserPasswordForOTP(t, user.Id, "Correct1!")

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Goiabada", AccountName: "adminreset@otp.test"})
	assert.NoError(t, err)
	secret := key.Secret()

	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)

	enable := api.UpdateAccountOTPRequest{
		Enabled:  true,
		Password: "Correct1!",
		OtpCode:  code,
	}

	// The account API enrolls the seed the server issued and no other, so both enables below have
	// to be staged against this same key rather than named in the request. A second call to the
	// issuing endpoint would mint a different secret, and the same code could not match twice
	// (#247).
	installPendingEnrollmentForTest(t, user.Id, key.URL(), time.Now().UTC())
	status, body := putAccountOTP(t, accessToken, enable)
	if status != http.StatusOK {
		t.Fatalf("expected the enable to succeed, got %d. body: %s", status, body)
	}

	// Disable through the admin endpoint, which is the site under test here.
	adminToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/otp"
	resp := makeAPIRequest(t, "PUT", url, adminToken, api.UpdateUserOTPRequest{Enabled: false})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The same code the enable already consumed. It is accepted only because the admin disable
	// reset the marker.
	skipIfOtpCodeOutsideWindow(t, secret, code)
	installPendingEnrollmentForTest(t, user.Id, key.URL(), time.Now().UTC())
	status, body = putAccountOTP(t, accessToken, enable)
	if status != http.StatusOK {
		t.Fatalf("expected the re-enable with the same code to succeed after the admin disable reset "+
			"the consumed-step marker, got %d. body: %s", status, body)
	}
}

func TestAPIUserOTPPut_EnableNotSupported(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without OTP
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@otp-enable.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
		OTPEnabled:    false,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Try to enable OTP (should fail)
	updateReq := api.UpdateUserOTPRequest{
		Enabled: true,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return bad request with specific error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIUserOTPPut_UserNotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Disable OTP for non-existent user
	updateReq := api.UpdateUserOTPRequest{
		Enabled: false,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/99999/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return not found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserOTPPut_OTPNotEnabled(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without OTP enabled
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@otp-not-enabled.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
		OTPEnabled:    false,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Test: Try to disable OTP when it's already disabled
	updateReq := api.UpdateUserOTPRequest{
		Enabled: false,
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return bad request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestAPIUserSessionGet tests the GET /api/v1/admin/user-sessions/{sessionIdentifier} endpoint
func TestAPIUserSessionGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "testuser@session.test",
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(nil, testUser)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(nil, testUser.Id)
	}()

	// Setup: Create test session
	testSession := &models.UserSession{
		SessionIdentifier: uuid.New().String(),
		Started:           time.Now().UTC(),
		LastAccessed:      time.Now().UTC(),
		AuthMethods:       "pwd",
		AcrLevel:          "urn:goiabada:pwd",
		AuthTime:          time.Now().UTC(),
		IpAddress:         "192.168.1.1",
		DeviceName:        "Test Device",
		DeviceType:        "computer",
		DeviceOS:          "linux",
		UserId:            testUser.Id,
	}
	err = database.CreateUserSession(nil, testSession)
	assert.NoError(t, err)
	defer func() {
		_ = database.DeleteUserSession(nil, testSession.Id)
	}()

	// Test: Get user session
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-sessions/" + testSession.SessionIdentifier
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getSessionResponse api.GetUserSessionResponse
	err = json.NewDecoder(resp.Body).Decode(&getSessionResponse)
	assert.NoError(t, err)

	// Assert: Session data should match
	assert.Equal(t, testSession.SessionIdentifier, getSessionResponse.Session.SessionIdentifier)
	assert.Equal(t, testSession.AuthMethods, getSessionResponse.Session.AuthMethods)
	assert.Equal(t, testSession.AcrLevel, getSessionResponse.Session.AcrLevel)
	assert.Equal(t, testSession.IpAddress, getSessionResponse.Session.IpAddress)
	assert.Equal(t, testSession.DeviceName, getSessionResponse.Session.DeviceName)
	assert.Equal(t, testSession.UserId, getSessionResponse.Session.UserId)
}

func TestAPIUserSessionGet_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get non-existent session
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-sessions/nonexistent-session"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return not found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// The PUT on this path was retired with the level2AuthConfigHasChanged mechanism it
// existed to drive: its request body carried that field and nothing else, so the endpoint
// had no other function (#242). GET and DELETE stay, so the path still exists and chi
// answers a PUT to it with 405 rather than 404.
func TestAPIUserSessionPut_MethodNotAllowed(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: PUT the session path, which no longer registers that method
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/user-sessions/" + uuid.New().String()
	resp := makeAPIRequest(t, "PUT", url, accessToken, map[string]interface{}{"level2AuthConfigHasChanged": true})
	defer func() { _ = resp.Body.Close() }()

	// Assert: The method is gone, not the path
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}
