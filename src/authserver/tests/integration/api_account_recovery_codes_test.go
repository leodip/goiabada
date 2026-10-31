package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The account API's recovery-code endpoints (#257 decisions 8 and 9), end to end: GET
// /api/v1/account/otp/recovery-codes answers how many of the caller's codes are unused, and POST,
// given the password, replaces the set with a new one, ends no session and moves no generation.

const recoveryCodesURL = "/api/v1/account/otp/recovery-codes"

// enableOTPForRecoveryCodesTest turns two-factor authentication on for the account user through the
// account API and answers the set the enable created.
func enableOTPForRecoveryCodesTest(t *testing.T, accessToken string, userId int64) []string {
	t.Helper()
	setUserPasswordForOTP(t, userId, "Correct1!")
	resetOTPStateForTest(t, userId)
	secret := getOTPEnrollment(t, accessToken).SecretKey
	status, body := putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{
		Enabled: true, Password: "Correct1!", OtpCode: otptest.Code(t, secret, time.Now()),
	})
	require.Equal(t, http.StatusOK, status, body)
	var enabled api.UpdateAccountOTPResponse
	require.NoError(t, json.Unmarshal([]byte(body), &enabled))
	require.Len(t, enabled.RecoveryCodes, 10)
	t.Cleanup(func() {
		resetOTPStateForTest(t, userId)
		require.NoError(t, database.DeleteUserRecoveryCodes(context.Background(), nil, userId))
	})
	return enabled.RecoveryCodes
}

func getRecoveryCodesRemaining(t *testing.T, accessToken string) int {
	t.Helper()
	resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+recoveryCodesURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var got api.AccountRecoveryCodesResponse
	require.NoError(t, json.Unmarshal(body, &got))
	return got.Remaining
}

func postRecoveryCodes(t *testing.T, accessToken string, password string) (int, []byte) {
	t.Helper()
	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+recoveryCodesURL, accessToken,
		api.CreateAccountRecoveryCodesRequest{Password: password})
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body
}

// claimRecoveryCodeForTest spends one code the way a sign-in does, by its hash, and says whether
// the set held it unused.
func claimRecoveryCodeForTest(t *testing.T, userId int64, code string) bool {
	t.Helper()
	used, err := database.TryUseUserRecoveryCode(context.Background(), nil, userId,
		hashutil.HashString(strings.ReplaceAll(code, "-", "")))
	require.NoError(t, err)
	return used
}

func TestAPIAccountRecoveryCodesGet_CountsTheUnusedCodes(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	codes := enableOTPForRecoveryCodesTest(t, accessToken, userId)

	assert.Equal(t, 10, getRecoveryCodesRemaining(t, accessToken), "a new set has ten unused codes")

	require.True(t, claimRecoveryCodeForTest(t, userId, codes[0]))
	require.True(t, claimRecoveryCodeForTest(t, userId, codes[1]))
	assert.Equal(t, 8, getRecoveryCodesRemaining(t, accessToken), "a used code is not counted")

	resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+recoveryCodesURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
}

// A new set replaces the old one at once: every old code stops working, used or not, and the ten
// new ones are the user's set. It ends no session and moves no generation, since the authenticator
// did not change (#257 decision 8).
func TestAPIAccountRecoveryCodesPost_ReplacesTheSet(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	oldCodes := enableOTPForRecoveryCodesTest(t, accessToken, userId)
	require.True(t, claimRecoveryCodeForTest(t, userId, oldCodes[0]))

	before, err := database.GetUserById(context.Background(), nil, userId)
	require.NoError(t, err)
	extra := seedExtraSessionForOTPTest(t, userId)

	status, body := postRecoveryCodes(t, accessToken, "Correct1!")
	require.Equal(t, http.StatusOK, status, string(body))
	var created api.CreateAccountRecoveryCodesResponse
	require.NoError(t, json.Unmarshal(body, &created))
	require.Len(t, created.RecoveryCodes, 10)
	for _, code := range created.RecoveryCodes {
		assert.Regexp(t, `^[0-9a-hjkmnp-tv-z]{4}(-[0-9a-hjkmnp-tv-z]{4}){5}$`, code)
		assert.NotContains(t, oldCodes, code)
	}

	assert.Equal(t, 10, getRecoveryCodesRemaining(t, accessToken), "the new set is ten unused codes")
	assert.False(t, claimRecoveryCodeForTest(t, userId, oldCodes[1]), "an unused code of the old set stops working")
	assert.True(t, claimRecoveryCodeForTest(t, userId, created.RecoveryCodes[3]), "a code of the new set works")

	after, err := database.GetUserById(context.Background(), nil, userId)
	require.NoError(t, err)
	assert.Equal(t, before.OtpConfigGeneration, after.OtpConfigGeneration, "a new set moves no generation")
	assert.True(t, after.OTPEnabled, "the authenticator is left as it is")
	reloaded, err := database.GetUserSessionById(context.Background(), nil, extra.Id)
	require.NoError(t, err)
	require.NotNil(t, reloaded, "a new set ends no session")
	assert.Equal(t, after.OtpConfigGeneration, reloaded.OtpConfigGeneration, "the session owes no re-prompt")
	assert.Equal(t, "pwd otp", reloaded.AuthMethods, "the session keeps its second factor")
	assert.Equal(t, 9, getRecoveryCodesRemaining(t, accessToken), "the caller's own token still works")
}

func TestAPIAccountRecoveryCodesPost_WrongPasswordIsRefused(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	codes := enableOTPForRecoveryCodesTest(t, accessToken, userId)

	status, body := postRecoveryCodes(t, accessToken, "WrongPwd!")
	assert.Equal(t, http.StatusBadRequest, status)
	var errResp api.ErrorResponse
	require.NoError(t, json.Unmarshal(body, &errResp))
	assert.Equal(t, "AUTHENTICATION_FAILED", errResp.ErrorCode)
	assert.NotContains(t, string(body), "recoveryCodes")
	assert.True(t, claimRecoveryCodeForTest(t, userId, codes[0]), "the set is left as it was")
}

func TestAPIAccountRecoveryCodesPost_NoAuthenticatorIsRefused(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")
	resetOTPStateForTest(t, userId)

	status, body := postRecoveryCodes(t, accessToken, "Correct1!")
	assert.Equal(t, http.StatusBadRequest, status)
	var errResp api.ErrorResponse
	require.NoError(t, json.Unmarshal(body, &errResp))
	assert.Equal(t, "OTP_NOT_ENABLED", errResp.ErrorCode)
	assert.Equal(t, 0, unusedRecoveryCodesForTest(t, userId), "no set is created without an authenticator")
}
