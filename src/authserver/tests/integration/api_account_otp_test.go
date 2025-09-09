package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"fmt"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// helper to set a user's password to a known value (reused pattern)
func setUserPasswordForOTP(t *testing.T, userId int64, newPassword string) {
	t.Helper()
	// Use admin API to set user password (does not require current password)
	adminToken, _ := createAdminClientWithToken(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" +
		fmt.Sprintf("%d", userId) + "/password"
	resp := makeAPIRequest(t, "PUT", url, adminToken, api.UpdateUserPasswordRequest{NewPassword: newPassword})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("failed to set user password via admin API, status=%d body=%s", resp.StatusCode, string(body))
	}

	// Verify password persisted and matches
	u2, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	assert.True(t, hashutil.VerifyPasswordHash(u2.PasswordHash, newPassword), "password hash should match new password")
}

// helper: get current account user id via profile for a given access token
func getAccountUserId(t *testing.T, accessToken string) int64 {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("failed to get account profile, status=%d body=%s", resp.StatusCode, string(body))
	}
	var getResp api.GetUserResponse
	err := json.NewDecoder(resp.Body).Decode(&getResp)
	assert.NoError(t, err)
	return getResp.User.Id
}

func TestAPIAccountOTPEnrollmentGet_Success(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	// Ensure OTP disabled on the account user
	u, _ := database.GetUserById(nil, userId)
	u.OTPEnabled = false
	u.OTPSecret = ""
	_ = database.UpdateUser(nil, u)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp/enrollment"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var enr api.AccountOTPEnrollmentResponse
	err := json.NewDecoder(resp.Body).Decode(&enr)
	assert.NoError(t, err)
	assert.NotEmpty(t, enr.Base64Image)
	assert.NotEmpty(t, enr.SecretKey)
}

func TestAPIAccountOTPEnrollmentGet_AlreadyEnabled(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	// Enable OTP on the account user directly
	u, _ := database.GetUserById(nil, userId)
	u.OTPEnabled = true
	u.OTPSecret = "JBSWY3DPEHPK3PXP" // base32 test secret
	_ = database.UpdateUser(nil, u)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp/enrollment"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "OTP is already enabled", errResp.Error.Message)
}

func TestAPIAccountOTPEnrollmentGet_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp/enrollment"

	// No token
	req, _ := http.NewRequest("GET", url, nil)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body1, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "Access token required", strings.TrimSpace(string(body1)))

	// Invalid token
	resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	assert.Equal(t, "Access token required", strings.TrimSpace(string(body2)))

	// Insufficient scope
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp3 := makeAPIRequest(t, "GET", url, tok, nil)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	body3, _ := io.ReadAll(resp3.Body)
	assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body3)))
}

func TestAPIAccountOTPPut_Enable_Success(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	// Set known password and ensure OTP disabled
	setUserPasswordForOTP(t, userId, "Correct1!")
	u, _ := database.GetUserById(nil, userId)
	u.OTPEnabled = false
	u.OTPSecret = ""
	_ = database.UpdateUser(nil, u)

	// Use a known base32 secret and generate a valid current code
	secret := "JBSWY3DPEHPK3PXP"
	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)

	reqBody := api.UpdateAccountOTPRequest{
		Enabled:   true,
		Password:  "Correct1!",
		OtpCode:   code,
		SecretKey: secret,
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}

	// Verify DB updated
	updated, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	assert.True(t, updated.OTPEnabled)
	assert.Equal(t, strings.ToUpper(secret), updated.OTPSecret)
}

func TestAPIAccountOTPPut_Enable_AuthFailed(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	reqBody := api.UpdateAccountOTPRequest{
		Enabled:   true,
		Password:  "WrongPwd!",
		OtpCode:   "000000",
		SecretKey: "JBSWY3DPEHPK3PXP",
	}
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Authentication failed. Check your password and try again.", errResp.Error.Message)
}

func TestAPIAccountOTPPut_Enable_InvalidFormats(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"

	// Invalid code format (non-digits)
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountOTPRequest{Enabled: true, Password: "Correct1!", OtpCode: "aaaaa", SecretKey: "JBSWY3DPEHPK3PXP"})
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "Invalid OTP code.", err1.Error.Message)

	// Invalid secret format (bad chars)
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountOTPRequest{Enabled: true, Password: "Correct1!", OtpCode: "123456", SecretKey: "INVALID!!!"})
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "Invalid OTP secret format.", err2.Error.Message)
}

func TestAPIAccountOTPPut_Enable_WrongCode(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	// Valid-looking secret and code format, but wrong code for the secret
	reqBody := api.UpdateAccountOTPRequest{Enabled: true, Password: "Correct1!", OtpCode: "000000", SecretKey: "JBSWY3DPEHPK3PXP"}
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Incorrect OTP Code. OTP codes are time-sensitive and change every 30 seconds. Make sure you're using the most recent code generated by your authenticator app.", errResp.Error.Message)
}

func TestAPIAccountOTPPut_Disable_Success(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	// Pre-enable OTP directly on the account user
	u, _ := database.GetUserById(nil, userId)
	u.OTPEnabled = true
	u.OTPSecret = "JBSWY3DPEHPK3PXP"
	_ = database.UpdateUser(nil, u)

	reqBody := api.UpdateAccountOTPRequest{Enabled: false, Password: "Correct1!"}
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}

	updated, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	assert.False(t, updated.OTPEnabled)
	assert.Equal(t, "", updated.OTPSecret)
}

func TestAPIAccountOTPPut_Enable_SetsSessionFlag(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	// Ensure OTP disabled for this account user
	u, _ := database.GetUserById(nil, userId)
	u.OTPEnabled = false
	u.OTPSecret = ""
	_ = database.UpdateUser(nil, u)

	// Prepare valid enable request
	secret := "JBSWY3DPEHPK3PXP"
	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)
	reqBody := api.UpdateAccountOTPRequest{Enabled: true, Password: "Correct1!", OtpCode: code, SecretKey: secret}
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}

	// Fetch sessions for this user and ensure at least one has the flag set
	sessions, err := database.GetUserSessionsByUserId(nil, userId)
	assert.NoError(t, err)
	found := false
	for i := range sessions {
		if sessions[i].Level2AuthConfigHasChanged {
			found = true
			break
		}
	}
	assert.True(t, found, "expected at least one session with Level2AuthConfigHasChanged=true")
}

func TestAPIAccountOTPPut_Disable_SetsSessionFlag(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	// Pre-enable OTP directly on this account user
	u, _ := database.GetUserById(nil, userId)
	u.OTPEnabled = true
	u.OTPSecret = "JBSWY3DPEHPK3PXP"
	_ = database.UpdateUser(nil, u)

	reqBody := api.UpdateAccountOTPRequest{Enabled: false, Password: "Correct1!"}
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}

	// Fetch sessions for this user and ensure at least one has the flag set
	sessions, err := database.GetUserSessionsByUserId(nil, userId)
	assert.NoError(t, err)
	found := false
	for i := range sessions {
		if sessions[i].Level2AuthConfigHasChanged {
			found = true
			break
		}
	}
	assert.True(t, found, "expected at least one session with Level2AuthConfigHasChanged=true")
}

func TestAPIAccountOTPPut_Disable_NotEnabled(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	// Ensure disabled on the account user
	u, _ := database.GetUserById(nil, userId)
	u.OTPEnabled = false
	u.OTPSecret = ""
	_ = database.UpdateUser(nil, u)

	reqBody := api.UpdateAccountOTPRequest{Enabled: false, Password: "Correct1!"}
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "User does not have OTP enabled", errResp.Error.Message)
}

func TestAPIAccountOTPPut_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"

	// No token
	req, _ := http.NewRequest("PUT", url, nil)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Insufficient scope
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp2 := makeAPIRequest(t, "PUT", url, tok, api.UpdateAccountOTPRequest{Enabled: false, Password: "x"})
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body2)))
}
