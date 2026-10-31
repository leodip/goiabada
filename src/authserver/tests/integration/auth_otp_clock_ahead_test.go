package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An authenticator code is accepted for the previous and the current 30-second step, and a code
// from the next step, which only a device whose clock runs ahead of the server's shows, is refused
// with a message to check the device's time (#142). It costs the user nothing: it is not charged
// to the otp rate tier, whose budget is 5 refusals per user per 15 minutes and always on, and it
// does not advance the authenticator's consecutive-failure count. These cases hold that at each of
// the three places a code is checked, by sending one more next-step code than the budget allows and
// then the current code, which is accepted.

// clockAheadMessage is what the user is told about a code from the next step.
const clockAheadMessage = "Your device's clock seems to be ahead. Check that its date and time are set " +
	"automatically, then enter the code your app shows."

// otpRateBudget is the otp tier's refusals per user per 15 minutes.
const otpRateBudget = 5

// assertClockAheadRefused asserts the OTP form was drawn again with the clock-ahead message, and
// leaves the page readable for the next submission.
func assertClockAheadRefused(t *testing.T, resp *http.Response) {
	t.Helper()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"expected the OTP form drawn again, got a redirect to %q", resp.Header.Get("Location"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body = io.NopCloser(bytes.NewReader(body))

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, clockAheadMessage, strings.TrimSpace(doc.Find(`[role="alert"]`).Text()))
}

// clockAheadRefusalsFor counts the auth_failed_otp records naming userId with reason clock_ahead.
func clockAheadRefusalsFor(t *testing.T, adminToken string, userId int64) int {
	t.Helper()

	logs, resp := getAuditLogs(t, adminToken, "auditEvent="+audit.EventAuthFailedOtp+"&size=200")
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	count := 0
	for _, entry := range logs.AuditLogs {
		var details map[string]any
		require.NoError(t, json.Unmarshal([]byte(entry.Details), &details))
		if id, ok := details["user_id"].(float64); ok && int64(id) == userId && details["reason"] == "clock_ahead" {
			count++
		}
	}
	return count
}

func TestAuthOtp_ANextStepCodeIsRefusedAsAClockRunningAhead(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)
	client, redirectUri, user, password, otpSecret := createLevel2MandatoryUser(t, true)

	httpClient, page, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
	for i := 0; i < otpRateBudget+1; i++ {
		refused := authenticateWithOtp(t, httpClient, otpUrl, page, otptest.NextStepCode(t, otpSecret))
		_ = page.Body.Close()
		assertClockAheadRefused(t, refused)
		page = refused
	}

	stored, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.Zero(t, stored.OtpConsecutiveFailures, "a next-step code is not counted against the authenticator")
	assert.Zero(t, stored.LastOTPStep, "and claims no step")
	assert.Equal(t, otpRateBudget+1, clockAheadRefusalsFor(t, adminToken, user.Id))

	// Past the budget, so this is accepted only because none of the refusals was charged.
	resp := authenticateWithOtp(t, httpClient, otpUrl, page, otptest.Code(t, otpSecret, time.Now()))
	_ = page.Body.Close()
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
}

func TestAuthOtp_ANextStepCodeOnTheSetupFormIsRefusedAsAClockRunningAhead(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)
	client, redirectUri, user, password, _ := createLevel2MandatoryUser(t, false)

	httpClient, page, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
	secret := getOtpSecretFromEnrollmentPage(t, page)
	for i := 0; i < otpRateBudget+1; i++ {
		refused := authenticateWithOtp(t, httpClient, otpUrl, page, otptest.NextStepCode(t, secret))
		_ = page.Body.Close()
		assertClockAheadRefused(t, refused)
		// Still the setup form, with the key the user has already scanned.
		assert.Equal(t, secret, getOtpSecretFromEnrollmentPage(t, refused))
		page = refused
	}

	stored, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.False(t, stored.OTPEnabled, "nothing was set up")
	assert.Zero(t, stored.LastOTPStep, "and no step was claimed")
	assert.Equal(t, otpRateBudget+1, clockAheadRefusalsFor(t, adminToken, user.Id))

	resp := passSetupRecoveryCodes(t, httpClient, authenticateWithOtp(t, httpClient, otpUrl, page, otptest.Code(t, secret, time.Now())))
	_ = page.Body.Close()
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
}

func TestAPIAccountOTPPut_Enable_ANextStepCodeIsRefusedAsAClockRunningAhead(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	userId := getAccountUserId(t, accessToken)
	setUserPasswordForOTP(t, userId, "Correct1!")
	resetOTPStateForTest(t, userId)

	issued := getOTPEnrollment(t, accessToken)

	status, body := putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{
		Enabled: true, Password: "Correct1!", OtpCode: otptest.NextStepCode(t, issued.SecretKey),
	})
	require.Equal(t, http.StatusBadRequest, status, body)
	var refusal api.ErrorResponse
	require.NoError(t, json.Unmarshal([]byte(body), &refusal))
	assert.Equal(t, "OTP_CLOCK_AHEAD", refusal.ErrorCode)
	assert.Equal(t, clockAheadMessage, refusal.ErrorDescription)
	assert.Equal(t, 1, clockAheadRefusalsFor(t, adminToken, userId))

	stored, err := database.GetUserById(context.Background(), nil, userId)
	require.NoError(t, err)
	assert.False(t, stored.OTPEnabled)
	assert.Zero(t, stored.LastOTPStep, "no step was claimed")

	// The current code, from the same issued key, enables.
	status, body = putAccountOTP(t, accessToken, api.UpdateAccountOTPRequest{
		Enabled: true, Password: "Correct1!", OtpCode: otptest.Code(t, issued.SecretKey, time.Now()),
	})
	assert.Equal(t, http.StatusOK, status, body)
}
