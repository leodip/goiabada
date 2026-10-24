package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIUserPasswordPut tests the PUT /api/v1/admin/users/{id}/password endpoint
func TestAPIUserPasswordPut_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@password.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
		PasswordHash:  "old-password-hash",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Test: Update password
	updateReq := api.UpdateUserPasswordRequest{
		NewPassword: "newSecurePassword123!",
	}
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/password"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)

	// Assert: User ID should match
	assert.Equal(t, testUser.Id, updateResponse.User.Id)

	// Verify password was actually updated in database
	updatedUser, err := database.GetUserById(context.Background(), nil, testUser.Id)
	require.NoError(t, err)
	assert.NotEqual(t, "old-password-hash", updatedUser.PasswordHash)

	// Verify new password can be validated
	assert.True(t, passwordhash.Verify(updatedUser.PasswordHash, updateReq.NewPassword))
}

// TestAPIUserPasswordPut_AtBcryptsBound sets a password of bcrypt's whole bound, which the first
// start may seed for the first administrator and which every password form accepts with it (#550),
// and checks that the stored hash verifies that password and nothing appended to it.
func TestAPIUserPasswordPut_AtBcryptsBound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@password-bound.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
		PasswordHash:  "old-password-hash",
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Every policy's character classes, at exactly the bound.
	password := "Aa1!" + strings.Repeat("a", passwordhash.MaxPasswordBytes-4)
	require.Len(t, password, passwordhash.MaxPasswordBytes)

	updateReq := api.UpdateUserPasswordRequest{NewPassword: password}
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/password"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	updatedUser, err := database.GetUserById(context.Background(), nil, testUser.Id)
	require.NoError(t, err)
	assert.True(t, passwordhash.Verify(updatedUser.PasswordHash, password), "the password set verifies")
	assert.False(t, passwordhash.Verify(updatedUser.PasswordHash, password+"x"),
		"bcrypt reads only the first 72 bytes, and Verify refuses what it would not read")
}

func TestAPIUserPasswordPut_ValidationError(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@password-validation.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	testCases := []struct {
		name     string
		password string
	}{
		{"empty password", ""},
		{"too short password", "123"},
		{"too long password", strings.Repeat("a", passwordhash.MaxPasswordBytes+1)}, // One past bcrypt's bound, the cap every password form applies
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			updateReq := api.UpdateUserPasswordRequest{
				NewPassword: tc.password,
			}
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/password"
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
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/99999/password"
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
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/invalid/password"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return bad request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestAPIUserOTPPut tests the PUT /api/v1/admin/users/{id}/otp endpoint
func TestAPIUserOTPPut_DisableSuccess(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user with OTP enabled. The address is the authenticator's
	// account name as well as the user's, so it is drawn once.
	otpEmail := uniqueEmail("testuser@otp.test")
	otpSecret := newOTPSecretForTest(t, otpEmail)

	testUser := &record.User{
		Subject:            fake.UUID(),
		Enabled:            true,
		Email:              otpEmail,
		GivenName:          "Test",
		FamilyName:         "User",
		EmailVerified:      true,
		OTPEnabled:         true,
		OTPSecretEncrypted: encryptOTPSecretForTest(t, otpSecret),
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Test: Disable OTP
	updateReq := api.UpdateUserOTPRequest{
		Enabled: false,
	}
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResponse api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResponse)
	require.NoError(t, err)

	// Assert: User ID should match and OTP should be disabled
	assert.Equal(t, testUser.Id, updateResponse.User.Id)
	assert.False(t, updateResponse.User.OTPEnabled)

	// Verify OTP was actually disabled in database
	updatedUser, err := database.GetUserById(context.Background(), nil, testUser.Id)
	require.NoError(t, err)
	assert.False(t, updatedUser.OTPEnabled)
	// The seed itself is gone, not merely unreachable (#98).
	assert.Empty(t, updatedUser.OTPSecretEncrypted)
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

	keyURL, secret := newOTPKeyURLForTest(t, "adminreset@otp.test")

	code := otptest.Code(t, secret, time.Now())

	enable := api.UpdateAccountOTPRequest{
		Enabled:  true,
		Password: "Correct1!",
		OtpCode:  code,
	}

	// The account API enrolls the seed the server issued and no other, so both enables below have
	// to be staged against this same key rather than named in the request. A second call to the
	// issuing endpoint would mint a different secret, and the same code could not match twice
	// (#247).
	installPendingEnrollmentForTest(t, user.Id, keyURL, time.Now().UTC())
	status, body := putAccountOTP(t, accessToken, enable)
	if status != http.StatusOK {
		t.Fatalf("expected the enable to succeed, got %d. body: %s", status, body)
	}

	// Disable through the admin endpoint, which is the site under test here.
	adminToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/otp"
	resp := makeAPIRequest(t, "PUT", url, adminToken, api.UpdateUserOTPRequest{Enabled: false})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The same code the enable already consumed. It is accepted only because the admin disable
	// reset the marker.
	skipIfOtpCodeOutsideWindow(t, secret, code)
	installPendingEnrollmentForTest(t, user.Id, keyURL, time.Now().UTC())
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
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@otp-enable.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
		OTPEnabled:    false,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Test: Try to enable OTP (should fail)
	updateReq := api.UpdateUserOTPRequest{
		Enabled: true,
	}
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/otp"
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
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/99999/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return not found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestAPIUserOTPPut_OTPNotEnabled(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user without OTP enabled
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@otp-not-enabled.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
		OTPEnabled:    false,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Test: Try to disable OTP when it's already disabled
	updateReq := api.UpdateUserOTPRequest{
		Enabled: false,
	}
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(testUser.Id, 10) + "/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return bad request
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestAPIUserSessionGet_Success reads a session by the numeric id a session list returns, and gets
// back the row that list carries: the stored fields, isCurrent, and the clients it authorized
// (#651 decisions 1 and 6).
func TestAPIUserSessionGet_Success(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Setup: Create test user
	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@session.test"),
		GivenName:     "Test",
		FamilyName:    "User",
		EmailVerified: true,
	}
	err := database.CreateUser(context.Background(), nil, testUser)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, testUser.Id)
	}()

	// Setup: A client the session authorized, shown to users under a name of its own
	testClient := &record.Client{
		ClientIdentifier:         "session-get-client-" + fake.UUID()[:8],
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		DisplayName:              "Session Portal",
		ShowDisplayName:          true,
	}
	err = database.CreateClient(context.Background(), nil, testClient)
	require.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, testClient.Id) }()

	// Setup: Create test session
	testSession := &record.UserSession{
		SessionIdentifier: fake.UUID(),
		Started:           time.Now().UTC(),
		LastAccessed:      time.Now().UTC(),
		AuthMethods:       "pwd",
		AcrLevel:          "urn:goiabada:pwd",
		AuthTime:          time.Now().UTC(),
		PasswordAuthTime:  time.Now().UTC(),
		IpAddress:         "192.168.1.1",
		DeviceName:        "Test Device",
		DeviceType:        "computer",
		DeviceOS:          "linux",
		UserId:            testUser.Id,
	}
	err = database.CreateUserSession(context.Background(), nil, testSession)
	require.NoError(t, err)
	defer func() {
		_ = database.DeleteUserSession(context.Background(), nil, testSession.Id)
	}()
	now := time.Now().UTC()
	err = database.CreateUserSessionClient(context.Background(), nil, &record.UserSessionClient{
		UserSessionId: testSession.Id, ClientId: testClient.Id, Started: now, LastAccessed: now,
	})
	require.NoError(t, err)

	// Test: Get user session by its numeric id
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-sessions/" + strconv.FormatInt(testSession.Id, 10)
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Response should be successful
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var getSessionResponse api.GetUserSessionResponse
	err = json.NewDecoder(resp.Body).Decode(&getSessionResponse)
	require.NoError(t, err)

	// Assert: Session data should match
	got := getSessionResponse.Session
	assert.Equal(t, testSession.Id, got.Id)
	assert.Equal(t, testSession.SessionIdentifier, got.SessionIdentifier)
	assert.Equal(t, testSession.AuthMethods, got.AuthMethods)
	assert.Equal(t, testSession.AcrLevel.String(), got.AcrLevel)
	assert.Equal(t, testSession.IpAddress, got.IpAddress)
	assert.Equal(t, testSession.DeviceName, got.DeviceName)
	assert.Equal(t, testSession.UserId, got.UserId)

	// Assert: The list row's fields, as the user's session list carries them
	assert.False(t, got.IsCurrent, "a client credentials token carries no sid, so no session is its own")
	assert.Equal(t, []string{testClient.ClientIdentifier}, got.ClientIdentifiers)
	assert.Equal(t, []api.SessionClientResponse{
		{ClientIdentifier: testClient.ClientIdentifier, Name: "Session Portal", NameUnverified: false},
	}, got.Clients)
}

// A session past the idle timeout or the maximum lifetime is gone to the API, with the same answer
// as an id naming no session, though the background worker has not swept its row yet (#651
// decision 4). Each is stored dead by its own timestamps against the deployment's settings.
func TestAPIUserSessionGet_ASessionNoLongerLiveIsNotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	idle := time.Duration(settings.UserSessionIdleTimeoutInSeconds) * time.Second
	lifetime := time.Duration(settings.UserSessionMaxLifetimeInSeconds) * time.Second
	require.Less(t, idle+10*time.Minute, lifetime, "the idle case must be dead by idle time alone")

	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@dead-session.test"),
		EmailVerified: true,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, testUser))
	defer func() { _ = database.DeleteUser(context.Background(), nil, testUser.Id) }()

	now := time.Now().UTC()
	for _, tc := range []struct {
		name         string
		started      time.Time
		lastAccessed time.Time
	}{
		{"past the idle timeout", now.Add(-idle - 10*time.Minute), now.Add(-idle - 5*time.Minute)},
		{"past the maximum lifetime", now.Add(-lifetime - 10*time.Minute), now.Add(-time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := createTestUserSession(t, testUser.Id, fake.UUID())
			defer func() { _ = database.DeleteUserSession(context.Background(), nil, session.Id) }()
			session.Started = tc.started
			session.LastAccessed = tc.lastAccessed
			require.NoError(t, database.UpdateUserSession(context.Background(), nil, session))

			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-sessions/" + strconv.FormatInt(session.Id, 10)
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			var body api.ErrorResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, "NOT_FOUND", body.ErrorCode)

			// Still stored: the 404 is the API's answer, not the sweep's.
			stored, err := database.GetUserSessionById(context.Background(), nil, session.Id)
			require.NoError(t, err)
			assert.NotNil(t, stored)
		})
	}
}

func TestAPIUserSessionGet_NotFound(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: Get non-existent session
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-sessions/99999999"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	// Assert: Should return not found
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body api.ErrorResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "NOT_FOUND", body.ErrorCode)
}

// The path takes the numeric id alone: the session identifier it used to take is refused as any
// other value that is not an integer, even when it names a stored session (#651 decision 1).
func TestAPIUserSessionGet_ANonIntegerIsAValidationError(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	testUser := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("testuser@session-by-sid.test"),
		EmailVerified: true,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, testUser))
	defer func() { _ = database.DeleteUser(context.Background(), nil, testUser.Id) }()
	session := createTestUserSession(t, testUser.Id, fake.UUID())
	defer func() { _ = database.DeleteUserSession(context.Background(), nil, session.Id) }()

	for _, value := range []string{session.SessionIdentifier, "abc"} {
		t.Run(value, func(t *testing.T) {
			url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-sessions/" + value
			resp := makeAPIRequest(t, "GET", url, accessToken, nil)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var body api.ErrorResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, "VALIDATION_ERROR", body.ErrorCode)
		})
	}
}

// The PUT on this path was retired with the level2AuthConfigHasChanged mechanism it
// existed to drive: its request body carried that field and nothing else, so the endpoint
// had no other function (#242). GET and DELETE stay, so the path still exists and the router
// answers a PUT to it with 405 rather than 404.
func TestAPIUserSessionPut_MethodNotAllowed(t *testing.T) {
	// Setup: Create admin client and get access token
	accessToken, _ := createAdminClientWithToken(t)

	// Test: PUT the session path, which no longer registers that method
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/user-sessions/" + fake.UUID()
	resp := makeAPIRequest(t, "PUT", url, accessToken, map[string]interface{}{"level2AuthConfigHasChanged": true})
	defer func() { _ = resp.Body.Close() }()

	// Assert: The method is gone, not the path
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}
