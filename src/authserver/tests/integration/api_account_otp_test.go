package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// setUserPasswordForOTP gives a user a known password, so the OTP endpoint's password check can be
// satisfied. It writes the hash directly.
//
// DO NOT change this back to the admin API (PUT /api/v1/admin/users/{id}/password). It used to do
// that, and #106 made it a credential change: setting a password now advances the user's
// authentication generation, terminates their sessions and revokes their refresh tokens. Since
// every caller below already holds an access token for THIS user, going through that endpoint
// invalidates the very token the test is about to use, and all eight OTP cases fail with "Session
// has been terminated". That was the change working correctly, not a regression.
//
// The subject of these tests is the OTP endpoint, so the password is fixture setup and must not
// have side effects of its own.
func setUserPasswordForOTP(t *testing.T, userId int64, newPassword string) {
	t.Helper()

	user, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	if user == nil {
		t.Fatalf("user %d not found", userId)
	}

	hash, err := hashutil.HashPassword(newPassword)
	assert.NoError(t, err)
	user.PasswordHash = hash
	err = database.UpdateUser(nil, user)
	assert.NoError(t, err)

	// Verify password persisted and matches
	u2, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	assert.True(t, hashutil.VerifyPasswordHash(u2.PasswordHash, newPassword), "password hash should match new password")
}

// helper: get current account user id via profile for a given access token
func getAccountUserId(t *testing.T, accessToken string) int64 {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/profile"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("failed to get account profile, status=%d body=%s", resp.StatusCode, string(body))
	}
	var getResp api.GetUserResponse
	err := json.NewDecoder(resp.Body).Decode(&getResp)
	assert.NoError(t, err)
	return getResp.User.Id
}

// putAccountOTP submits one PUT /api/v1/account/otp and returns its status together with the
// response body, so the #111 reset cases can drive several enables and disables in a row without
// repeating the request shape or asserting an outcome the caller has not chosen.
func putAccountOTP(t *testing.T, accessToken string, reqBody api.UpdateAccountOTPRequest) (int, string) {
	t.Helper()

	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	return resp.StatusCode, string(body)
}

// skipIfOtpCodeOutsideWindow skips when code no longer matches secret at this instant. The reset
// cases below submit one code across several endpoint calls, and a period boundary crossed
// mid-test takes that code out of the acceptance window: the enable then fails because the matcher
// refused the code, not because the marker was never reset. Without this guard such a run reads as
// a reset regression, which is a case failing for the wrong reason (#111).
func skipIfOtpCodeOutsideWindow(t *testing.T, secret string, code string) {
	t.Helper()

	if _, matched := otp.MatchStep(code, secret, time.Now().UTC()); !matched {
		t.Skip("the code fell outside the acceptance window before the re-enable, so the matcher " +
			"would refuse it for a reason unrelated to the reset")
	}
}

// wrongOtpCodeFor is six digits that pass the handler's shape checks and that the matcher refuses for
// this secret at this instant, so a case asserting "Incorrect OTP Code" fails only when the handler
// stops refusing a code it should refuse.
//
// A fixed literal cannot do this job. TOTP emits every six-digit value eventually, so a hardcoded
// "wrong" code is not wrong, it is one that has not come up yet: for JBSWY3DPEHPK3PXP the matcher
// accepts 222222 from 2026-12-04T22:43:00Z, 111111 from 2027-10-31T16:26:00Z and 000000 from
// 2028-04-13T15:03:00Z, and MatchStep accepts the step either side, so each is live for about 90
// seconds and again at every later step that produces it. Walking the candidates and asking the
// matcher is what makes the choice hold at any date. Same approach as wrongButWellFormedCode in
// handler_api_account_otp_test.go.
func wrongOtpCodeFor(t *testing.T, secret string) string {
	t.Helper()

	for _, candidate := range []string{"000000", "111111", "222222"} {
		if _, matched := otp.MatchStep(candidate, secret, time.Now().UTC()); !matched {
			return candidate
		}
	}

	t.Fatal("could not find a six-digit code that the secret refuses")
	return ""
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
	defer func() { _ = resp.Body.Close() }()

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
	u.OTPSecretEncrypted = encryptOTPSecretForTest(t, "JBSWY3DPEHPK3PXP")
	_ = database.UpdateUser(nil, u)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp/enrollment"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "OTP is already enabled", errResp.ErrorDescription)
}

func TestAPIAccountOTPEnrollmentGet_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp/enrollment"

	// No token
	req, _ := http.NewRequest("GET", url, nil)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body1, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(body1), "Access token required.")

	// Invalid token
	resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(body2), "Access token required.")

	// Insufficient scope
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp3 := makeAPIRequest(t, "GET", url, tok, nil)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	body3, _ := io.ReadAll(resp3.Body)
	assert.Contains(t, string(body3), "Insufficient scope.")
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}

	// Verify DB updated
	updated, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	assert.True(t, updated.OTPEnabled)
	assert.Empty(t, updated.OTPSecret)
	decrypted, err := updated.GetOTPSecret()
	assert.NoError(t, err)
	assert.Equal(t, strings.ToUpper(secret), decrypted)
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
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Authentication failed. Check your password and try again.", errResp.ErrorDescription)
}

func TestAPIAccountOTPPut_Enable_InvalidFormats(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"

	// Invalid code format (non-digits)
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountOTPRequest{Enabled: true, Password: "Correct1!", OtpCode: "aaaaa", SecretKey: "JBSWY3DPEHPK3PXP"})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "Invalid OTP code.", err1.ErrorDescription)

	// Invalid secret format (bad chars)
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountOTPRequest{Enabled: true, Password: "Correct1!", OtpCode: "123456", SecretKey: "INVALID!!!"})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "Invalid OTP secret format.", err2.ErrorDescription)
}

func TestAPIAccountOTPPut_Enable_WrongCode(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	// Valid-looking secret and code format, but a code the matcher refuses for that secret right now
	const secret = "JBSWY3DPEHPK3PXP"
	reqBody := api.UpdateAccountOTPRequest{Enabled: true, Password: "Correct1!", OtpCode: wrongOtpCodeFor(t, secret), SecretKey: secret}
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Incorrect OTP Code. OTP codes are time-sensitive and change every 30 seconds. Make sure you're using the most recent code generated by your authenticator app.", errResp.ErrorDescription)
}

func TestAPIAccountOTPPut_Disable_Success(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	// Pre-enable OTP directly on the account user
	u, _ := database.GetUserById(nil, userId)
	u.OTPEnabled = true
	u.OTPSecret = "JBSWY3DPEHPK3PXP"
	u.OTPSecretEncrypted = encryptOTPSecretForTest(t, "JBSWY3DPEHPK3PXP")
	_ = database.UpdateUser(nil, u)

	reqBody := api.UpdateAccountOTPRequest{Enabled: false, Password: "Correct1!"}
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}

	updated, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	assert.False(t, updated.OTPEnabled)
	assert.Equal(t, "", updated.OTPSecret)
}

// TestAPIAccountOTPPut_Disable_ResetsConsumedStep is seam 4's pin for #111 decision 4: disabling
// OTP returns the consumed-step marker to 0, so the same code can enroll an authenticator again.
//
// **Keep this case.** It asserts that one code is accepted twice, which reads like exactly the
// replay #111 exists to refuse, and it is the only test that fails if ResetUserOTPStep is dropped
// from the disable path. The marker belongs to the enrolled authenticator, so removing the
// authenticator clears it, and nothing is bypassed: disabling requires the password and enrolling
// requires possession of a secret. It is also the only in-product remedy if a clock jump strands a
// user's marker in the future, which without the reset would lock them out of OTP permanently.
//
// Endpoint-observable throughout. Nothing here reads users.last_otp_step, which would pass with
// the endpoints broken.
func TestAPIAccountOTPPut_Disable_ResetsConsumedStep(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Goiabada", AccountName: "reset@otp.test"})
	assert.NoError(t, err)
	secret := key.Secret()

	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)

	enable := api.UpdateAccountOTPRequest{
		Enabled:   true,
		Password:  "Correct1!",
		OtpCode:   code,
		SecretKey: secret,
	}

	status, body := putAccountOTP(t, accessToken, enable)
	if status != http.StatusOK {
		t.Fatalf("expected the first enable to succeed, got %d. body: %s", status, body)
	}

	status, body = putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{Password: "Correct1!"})
	if status != http.StatusOK {
		t.Fatalf("expected the disable to succeed, got %d. body: %s", status, body)
	}

	// The same code again. It was consumed by the first enable, so this succeeds only because the
	// disable reset the marker.
	skipIfOtpCodeOutsideWindow(t, secret, code)
	status, body = putAccountOTP(t, accessToken, enable)
	if status != http.StatusOK {
		t.Fatalf("expected the re-enable with the same code to succeed after the disable reset the "+
			"consumed-step marker, got %d. body: %s", status, body)
	}
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
	defer func() { _ = resp.Body.Close() }()
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
	u.OTPSecretEncrypted = encryptOTPSecretForTest(t, "JBSWY3DPEHPK3PXP")
	_ = database.UpdateUser(nil, u)

	reqBody := api.UpdateAccountOTPRequest{Enabled: false, Password: "Correct1!"}
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
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
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "User does not have OTP enabled", errResp.ErrorDescription)
}

func TestAPIAccountOTPPut_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"

	// No token
	req, _ := http.NewRequest("PUT", url, nil)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Insufficient scope
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp2 := makeAPIRequest(t, "PUT", url, tok, api.UpdateAccountOTPRequest{Enabled: false, Password: "x"})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(body2), "Insufficient scope.")
}
