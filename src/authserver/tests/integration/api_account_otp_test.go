package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
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

// -----------------------------------------------------------------------------
// The enrollment contract (#247)
//
// The server issues the enrollment and enrolls that seed and no other. Every enable case below
// therefore starts by asking for one, which is what a caller now has to do, and the cases that
// exercise the boundaries of the pending window install one directly.

// getOTPEnrollment calls the issuing endpoint and returns what it answered. This is the only way a
// caller can obtain a seed the PUT will accept.
func getOTPEnrollment(t *testing.T, accessToken string) api.AccountOTPEnrollmentResponse {
	t.Helper()

	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp/enrollment"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected the enrollment to be issued, got %d. body: %s", resp.StatusCode, string(body))
	}

	var enrollment api.AccountOTPEnrollmentResponse
	assert.NoError(t, json.NewDecoder(resp.Body).Decode(&enrollment))
	return enrollment
}

// resetOTPStateForTest returns the account user to "not enrolled, nothing pending". The cases share
// one user, so a pending enrollment left behind by an earlier case would decide a later one.
func resetOTPStateForTest(t *testing.T, userId int64) {
	t.Helper()

	user, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	user.OTPEnabled = false
	user.ClearOTPSecret()
	assert.NoError(t, database.UpdateUser(nil, user))
	assert.NoError(t, database.ClearPendingOTPEnrollment(nil, userId))
}

// installPendingEnrollmentForTest stages an enrollment as though the server had issued it at
// issuedAt, which is fixture setup no caller can perform: the issuing endpoint always stamps now,
// so an expired pending value cannot be reached through HTTP without waiting a quarter of an hour.
//
// It is the only place in this file that writes the pending columns. Every assertion below still
// observes the endpoints, never the row.
func installPendingEnrollmentForTest(t *testing.T, userId int64, keyURL string, issuedAt time.Time) {
	t.Helper()

	assert.NoError(t, database.ClearPendingOTPEnrollment(nil, userId))

	ciphertext, err := encryption.EncryptData(keyURL)
	assert.NoError(t, err)

	installed, err := database.TryInstallPendingOTPEnrollment(nil, userId, ciphertext, issuedAt,
		time.Now().UTC().Add(time.Hour))
	assert.NoError(t, err)
	assert.True(t, installed, "the fixture must have installed the pending enrollment")
}

// newOTPKeyURLForTest mints a key the same way the server does, for the cases that need to know the
// seed before the endpoint issues one.
func newOTPKeyURLForTest(t *testing.T, account string) (keyURL string, secret string) {
	t.Helper()

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Goiabada", AccountName: account})
	assert.NoError(t, err)
	return key.URL(), key.Secret()
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

	// The seed comes from the issuing endpoint, which is the only one the PUT will accept.
	assert.NoError(t, database.ClearPendingOTPEnrollment(nil, userId))
	secret := getOTPEnrollment(t, accessToken).SecretKey
	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)

	reqBody := api.UpdateAccountOTPRequest{
		Enabled:  true,
		Password: "Correct1!",
		OtpCode:  code,
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
		Enabled:  true,
		Password: "WrongPwd!",
		OtpCode:  "000000",
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
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountOTPRequest{Enabled: true, Password: "Correct1!", OtpCode: "aaaaa"})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "Invalid OTP code.", err1.ErrorDescription)

	// There is no secret-format row any more. The caller no longer supplies a secret, so
	// INVALID_OTP_SECRET became unreachable and was retired with the field (#247 decision 13).
	// The shape check above still runs before the pending enrollment is looked up, which is why
	// this case needs no enrollment of its own.
}

func TestAPIAccountOTPPut_Enable_WrongCode(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	// A well-formed code that the matcher refuses for the seed the server just issued.
	resetOTPStateForTest(t, userId)
	secret := getOTPEnrollment(t, accessToken).SecretKey
	reqBody := api.UpdateAccountOTPRequest{Enabled: true, Password: "Correct1!", OtpCode: wrongOtpCodeFor(t, secret)}
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

	// The two enables must use the same secret, or the same code could not match twice and the
	// case would prove nothing about the marker. A second call to the issuing endpoint would mint
	// a different one, so the pending enrollment is staged directly here instead (#247).
	keyURL, secret := newOTPKeyURLForTest(t, "reset@otp.test")

	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)

	enable := api.UpdateAccountOTPRequest{
		Enabled:  true,
		Password: "Correct1!",
		OtpCode:  code,
	}

	installPendingEnrollmentForTest(t, userId, keyURL, time.Now().UTC())
	status, body := putAccountOTP(t, accessToken, enable)
	if status != http.StatusOK {
		t.Fatalf("expected the first enable to succeed, got %d. body: %s", status, body)
	}

	status, body = putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{Password: "Correct1!"})
	if status != http.StatusOK {
		t.Fatalf("expected the disable to succeed, got %d. body: %s", status, body)
	}

	// The same code again. It was consumed by the first enable, so this succeeds only because the
	// disable reset the marker. The pending enrollment is restaged with the same key, since the
	// first enable cleared it inside the transaction that established the authenticator.
	skipIfOtpCodeOutsideWindow(t, secret, code)
	installPendingEnrollmentForTest(t, userId, keyURL, time.Now().UTC())
	status, body = putAccountOTP(t, accessToken, enable)
	if status != http.StatusOK {
		t.Fatalf("expected the re-enable with the same code to succeed after the disable reset the "+
			"consumed-step marker, got %d. body: %s", status, body)
	}
}

// seedExtraSessionForOTPTest adds a second session for the user, standing in for another device
// they are logged in on. Written straight to the database rather than driven through a ceremony,
// because what these cases are about is the REACH of the counter advance rather than how a session
// came to exist.
//
// Its snapshot is set to the user's current counter, so before the endpoint is called it owes no
// re-prompt. That is what makes the assertion below meaningful: the row starts out satisfied.
func seedExtraSessionForOTPTest(t *testing.T, userId int64) *models.UserSession {
	t.Helper()

	current, err := database.GetUserById(nil, userId)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	session := &models.UserSession{
		SessionIdentifier:   uuid.New().String(),
		Started:             now,
		LastAccessed:        now,
		AuthMethods:         "pwd otp",
		AcrLevel:            enums.AcrLevel2Optional.String(),
		AuthTime:            now,
		IpAddress:           "10.0.0.1",
		DeviceName:          "another device",
		DeviceType:          "mobile",
		DeviceOS:            "Android",
		OtpConfigGeneration: current.OtpConfigGeneration,
		UserId:              userId,
	}
	if err := database.CreateUserSession(nil, session); err != nil {
		t.Fatal(err)
	}
	return session
}

// assertEverySessionOwesAReprompt is the assertion parts 1.2 and 1.3 come down to: after an
// authenticator change, EVERY session of that user is behind the user's counter, not just the one
// the caller happened to be holding.
//
// The old mechanism could not satisfy this. It set a boolean on the single session named by the
// caller's own sid claim, so the tests that stood here asked only for "at least one session with
// the flag set", which is true of a mechanism that reaches exactly one and false of nothing.
func assertEverySessionOwesAReprompt(t *testing.T, userId int64, atLeast int) {
	t.Helper()

	user, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)

	sessions, err := database.GetUserSessionsByUserId(nil, userId)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(sessions), atLeast,
		"the fixture must leave at least %d sessions for this to be about reach at all", atLeast)

	for i := range sessions {
		assert.NotEqual(t, user.OtpConfigGeneration, sessions[i].OtpConfigGeneration,
			"session %s must owe a level 2 re-prompt: the user's counter is %d and its snapshot is %d",
			sessions[i].SessionIdentifier, user.OtpConfigGeneration, sessions[i].OtpConfigGeneration)
	}
}

// TestAPIAccountOTPPut_Enable_AdvancesOtpConfigGeneration covers part 1.2 and part 1.3 of #242 at
// the account API's enable branch.
//
// Part 1.2: the advance is one statement against one users row, so every session of that user owes
// a re-prompt afterwards. The second session seeded below is the one the old per-sid writer could
// never have reached.
//
// Part 1.3: the access token this suite mints carries no sid claim, so the old writer reached NO
// session at all here. The counter does not consult the claim, and the fact that this case passes
// with such a token is the whole of that half.
func TestAPIAccountOTPPut_Enable_AdvancesOtpConfigGeneration(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	// Ensure OTP disabled for this account user
	u, _ := database.GetUserById(nil, userId)
	u.OTPEnabled = false
	u.OTPSecret = ""
	_ = database.UpdateUser(nil, u)

	before, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	extra := seedExtraSessionForOTPTest(t, userId)

	// Prepare valid enable request, against the seed the server issues for it
	assert.NoError(t, database.ClearPendingOTPEnrollment(nil, userId))
	secret := getOTPEnrollment(t, accessToken).SecretKey
	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)
	reqBody := api.UpdateAccountOTPRequest{Enabled: true, Password: "Correct1!", OtpCode: code}
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}

	after, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	assert.Equal(t, before.OtpConfigGeneration+1, after.OtpConfigGeneration,
		"enabling an authenticator advances the counter by exactly one")

	assertEverySessionOwesAReprompt(t, userId, 2)

	// Named explicitly as well as covered by the sweep above, because this is the row the
	// mechanism this replaces could not reach: it was created before the call, its snapshot
	// was current at that moment, and nothing about the request mentions it.
	reloaded, err := database.GetUserSessionById(nil, extra.Id)
	assert.NoError(t, err)
	assert.NotEqual(t, after.OtpConfigGeneration, reloaded.OtpConfigGeneration,
		"the user's other device must owe a re-prompt too")
}

// TestAPIAccountOTPPut_Disable_AdvancesOtpConfigGeneration is the same property in the disable
// direction, where the stale assertion is the more dangerous one: a session whose amr still reads
// ["pwd","otp"] is naming an authenticator the user has removed.
func TestAPIAccountOTPPut_Disable_AdvancesOtpConfigGeneration(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")

	// Pre-enable OTP directly on this account user
	u, _ := database.GetUserById(nil, userId)
	u.OTPEnabled = true
	u.OTPSecret = "JBSWY3DPEHPK3PXP"
	u.OTPSecretEncrypted = encryptOTPSecretForTest(t, "JBSWY3DPEHPK3PXP")
	_ = database.UpdateUser(nil, u)

	before, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	extra := seedExtraSessionForOTPTest(t, userId)

	reqBody := api.UpdateAccountOTPRequest{Enabled: false, Password: "Correct1!"}
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}

	after, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	assert.Equal(t, before.OtpConfigGeneration+1, after.OtpConfigGeneration,
		"disabling an authenticator advances the counter by exactly one")

	assertEverySessionOwesAReprompt(t, userId, 2)

	reloaded, err := database.GetUserSessionById(nil, extra.Id)
	assert.NoError(t, err)
	assert.NotEqual(t, after.OtpConfigGeneration, reloaded.OtpConfigGeneration,
		"the user's other device must owe a re-prompt too")
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

// -----------------------------------------------------------------------------
// Seam G: the enrollment contract as a caller sees it (#247)

// The issuing endpoint is idempotent while an enrollment is pending. This is the reload bug, and it
// is the one a user actually hits: every call used to mint a fresh secret, so refreshing the
// enrollment page silently replaced the seed behind a QR code they had already scanned, and every
// code they then read off it was checked against a secret they were never shown.
//
// The image is asserted as well as the seed. They are two views of one stored otpauth:// URL, and a
// second call that answered with the same seed but a newly rendered image would still be handing
// the user a different QR code to scan.
func TestAPIAccountOTPEnrollmentGet_IsIdempotentWhileOnePending(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	resetOTPStateForTest(t, userId)

	first := getOTPEnrollment(t, accessToken)
	second := getOTPEnrollment(t, accessToken)

	assert.Equal(t, first.SecretKey, second.SecretKey,
		"a reload must not replace the seed behind a QR code the user has already scanned")
	assert.Equal(t, first.Base64Image, second.Base64Image,
		"nor the QR code itself")
	assert.NotEmpty(t, first.SecretKey)
}

// A pending enrollment older than the lifetime is replaced rather than honoured, so an abandoned
// one does not sit on the account forever.
func TestAPIAccountOTPEnrollmentGet_ReplacesAnExpiredEnrollment(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	resetOTPStateForTest(t, userId)

	keyURL, staleSecret := newOTPKeyURLForTest(t, "expired@otp.test")
	installPendingEnrollmentForTest(t, userId, keyURL, time.Now().UTC().Add(-20*time.Minute))

	issued := getOTPEnrollment(t, accessToken)
	assert.NotEqual(t, staleSecret, issued.SecretKey,
		"an expired enrollment must not be handed out again")

	// And the replacement is itself pending, so the caller can still complete it.
	assert.Equal(t, issued.SecretKey, getOTPEnrollment(t, accessToken).SecretKey)
}

// A request still carrying secretKey is refused, loudly and by name. Decision 13 chose the break so
// an integrator learns at once rather than wondering which secret was enrolled.
//
// The body is built as a raw map because api.UpdateAccountOTPRequest no longer has the field, which
// is exactly the change this asserts the server enforces.
func TestAPIAccountOTPPut_Enable_RefusesACallerSuppliedSecret(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")
	resetOTPStateForTest(t, userId)

	issued := getOTPEnrollment(t, accessToken)
	code, err := totp.GenerateCode(issued.SecretKey, time.Now())
	assert.NoError(t, err)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp"
	resp := makeAPIRequest(t, "PUT", url, accessToken, map[string]interface{}{
		"enabled":   true,
		"password":  "Correct1!",
		"otpCode":   code,
		"secretKey": issued.SecretKey,
	})
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "SECRET_KEY_NOT_ACCEPTED", errResp.ErrorCode)
	assert.Contains(t, errResp.ErrorDescription, "/api/v1/account/otp/enrollment")

	// Refused, not partially applied, observed the way a caller can observe it: the issuing
	// endpoint still answers, and still with the same seed. That says two things at once. It
	// says the authenticator was not established, because the GET refuses outright once OTP is
	// on, which is what TestAPIAccountOTPPut_Enable_EnrolsTheIssuedSeedAndClearsThePending
	// asserts in its tail. And it says the pending enrollment was not consumed either, which
	// reading users.otp_enabled could never have told us.
	assert.Equal(t, issued.SecretKey, getOTPEnrollment(t, accessToken).SecretKey,
		"a refused request must leave the pending enrollment exactly as it was")
}

// With no pending enrollment there is nothing to enroll, and the request is refused rather than
// falling back to anything. A partially migrated or rolled back deployment therefore fails closed.
func TestAPIAccountOTPPut_Enable_RefusedWithNoPendingEnrollment(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")
	resetOTPStateForTest(t, userId)

	// A well-formed code for a secret the server never issued, which is precisely what must not
	// be enrollable.
	_, strangerSecret := newOTPKeyURLForTest(t, "stranger@otp.test")
	code, err := totp.GenerateCode(strangerSecret, time.Now())
	assert.NoError(t, err)

	status, body := putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{
		Enabled: true, Password: "Correct1!", OtpCode: code,
	})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body, "OTP_ENROLLMENT_NOT_PENDING")

	// Nothing was partially applied, said the way a caller can hear it: the issuing endpoint
	// still issues. It refuses with 400 once OTP is on, so a 200 here is the observable form of
	// "the stranger's seed did not become this account's authenticator".
	assert.NotEmpty(t, getOTPEnrollment(t, accessToken).SecretKey,
		"a refused enable must leave the account still able to start an enrollment")
}

// An expired enrollment is no enrollment: the same refusal, and the seed cannot be redeemed late.
func TestAPIAccountOTPPut_Enable_RefusedWithAnExpiredEnrollment(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")
	resetOTPStateForTest(t, userId)

	keyURL, secret := newOTPKeyURLForTest(t, "expired-put@otp.test")
	installPendingEnrollmentForTest(t, userId, keyURL, time.Now().UTC().Add(-20*time.Minute))

	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)

	status, body := putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{
		Enabled: true, Password: "Correct1!", OtpCode: code,
	})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body, "OTP_ENROLLMENT_NOT_PENDING")
}

// The whole contract in one pass: the GET issues, the PUT enrolls that seed and no other, and the
// pending pair is gone afterwards.
//
// EVERY ASSERTION IS ENDPOINT-OBSERVABLE, which is what seam G is for. "The authenticator installed
// is the one the server issued" is proved by using it: a fresh level 2 authorization ceremony is
// driven to the OTP form and a code from the issued seed is accepted. Decrypting
// users.otp_secret_encrypted and comparing would assert the same equality one layer below the
// behaviour anyone actually depends on, and it would keep passing if the browser ceremony could not
// verify against what was stored. The direct column reads belong to seam F, which owns them on all
// four engines in tests/data/otp_enrollment_test.go: TestTryInstallPendingOTPEnrollment_RoundTrip
// for the write and read back, TestEnableUserOTPTx_ClearsThePendingEnrollment for the clear.
//
// Loading the user is fixture setup rather than an assertion: the ceremony driver takes a
// *models.User for its email, and no caller of this API has one.
func TestAPIAccountOTPPut_Enable_EnrolsTheIssuedSeedAndClearsThePending(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")
	resetOTPStateForTest(t, userId)

	issued := getOTPEnrollment(t, accessToken)
	code, err := totp.GenerateCode(issued.SecretKey, time.Now())
	assert.NoError(t, err)

	status, body := putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{
		Enabled: true, Password: "Correct1!", OtpCode: code,
	})
	if status != http.StatusOK {
		t.Fatalf("expected the enrollment to succeed, got %d. body: %s", status, body)
	}

	// The authenticator works, and it is the issued seed that drives it. A fresh cookie jar and a
	// level2_mandatory client put the browser at the OTP form, where the code is verified against
	// what the enable branch stored; nothing but the right secret gets past it.
	//
	// nextStepCode rather than the code above: the enable branch claims its time step through
	// TryConsumeUserOTPStep (#111), so resubmitting the spent code would be refused correctly and
	// would read here as a broken enrollment. The helper also skips, rather than failing, when the
	// two codes cannot be ordered.
	user, err := database.GetUserById(nil, userId)
	assert.NoError(t, err)
	ceremonyClient, ceremonyRedirectUri := createLevel2MandatoryClient(t)

	httpClient, otpPage, otpUrl := startOtpCeremony(t, ceremonyClient, ceremonyRedirectUri,
		user, "Correct1!", "")
	accepted := authenticateWithOtp(t, httpClient, otpUrl, otpPage,
		nextStepCode(t, issued.SecretKey, code))
	_ = otpPage.Body.Close()
	assertRedirect(t, accepted, "/auth/completed")
	_ = accepted.Body.Close()

	// And the issuing endpoint now refuses, because enrollment is over for this user. That is the
	// pending pair's clear as a caller can see it: a live pending enrollment would have been
	// answered with, and this account has none.
	url := config.GetAuthServer().BaseURL + "/api/v1/account/otp/enrollment"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
