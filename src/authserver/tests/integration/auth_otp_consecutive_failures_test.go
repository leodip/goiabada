package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthOtp_TheHundredthWrongCodeDisablesTheAuthenticatorUntilANewOneIsSetUp is #489 end to end,
// through /auth/otp: a user one refusal short of record.OtpConsecutiveFailureLimit sends a wrong
// code, which disables the authenticator and is audited once as otp_authenticator_disabled. The
// right code is then refused like any wrong one, and the admin API says the authenticator is
// disabled. An administrator sets a new password and then turns two-factor authentication off, which
// is the way back the docs give: the old password, which whoever sent the codes knew, is refused, and
// the user's next sign-in with the new one sets up a new authenticator, which starts with no failures
// against it, and the sign-in after that is accepted on the new authenticator's code.
func TestAuthOtp_TheHundredthWrongCodeDisablesTheAuthenticatorUntilANewOneIsSetUp(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, _ := createAdminClientWithToken(t)
	client, redirectUri, user, password, otpSecret := createLevel2MandatoryUser(t, true)

	// Seeded one short of the limit through the count's own statement, since reaching it through
	// the form would take 99 refusals behind the otp rate tier's 5 per 15 minutes.
	for i := 0; i < record.OtpConsecutiveFailureLimit-1; i++ {
		disabled, err := database.IncrementUserOtpConsecutiveFailures(context.Background(), nil, user.Id,
			user.OtpConfigGeneration)
		require.NoError(t, err)
		require.False(t, disabled)
	}

	httpClient, otpPage, otpUrl := startOtpCeremony(t, client, redirectUri, user, password, "")
	right := otptest.Code(t, otpSecret, time.Now())

	// The 100th refusal disables the authenticator.
	refused := authenticateWithOtp(t, httpClient, otpUrl, otpPage, wrongCodeBeside(right))
	_ = otpPage.Body.Close()
	assertOtpRefused(t, refused)

	// From then on the right code is refused too, with the same answer a wrong one gets.
	refusedAgain := authenticateWithOtp(t, httpClient, otpUrl, refused, right)
	_ = refused.Body.Close()
	assertOtpRefused(t, refusedAgain)
	_ = refusedAgain.Body.Close()

	stored, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.EqualValues(t, record.OtpConsecutiveFailureLimit, stored.OtpConsecutiveFailures)
	assert.Zero(t, stored.LastOTPStep, "the refused right code claimed no step")

	assert.Equal(t, 1, disabledEventsFor(t, adminToken, user.Id),
		"the disable is audited once: by the refusal that reached the limit, not by the one after it")

	shown := adminUser(t, adminToken, user.Id)
	assert.True(t, shown.OTPEnabled, "the authenticator is still there")
	assert.True(t, shown.OTPAuthenticatorDisabled, "and the admin API says it is disabled")

	// The way back: an administrator sets a new password, since whoever sent the codes knew the old
	// one, and then turns two-factor authentication off, as the console's one save does.
	newPassword := fake.Password(16)
	resp, _ := sendAdmin(t, adminToken, http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/password", user.Id),
		map[string]any{"newPassword": newPassword})
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	removeAuthenticatorAsAdministrator(t, user.Id)
	shown = adminUser(t, adminToken, user.Id)
	assert.False(t, shown.OTPEnabled)
	assert.False(t, shown.OTPAuthenticatorDisabled, "with no authenticator, nothing is disabled")

	// Whoever sent the codes can no longer sign in with the old password.
	assertPasswordRefusedAt(t, client, redirectUri, user, password)

	// At a level 3 client, the next sign-in, with the new password, sets up a new authenticator.
	httpClient, otpPage, otpUrl = startOtpCeremony(t, client, redirectUri, user, newPassword, "")
	newSecret := getOtpSecretFromEnrollmentPage(t, otpPage)
	require.NotEqual(t, otpSecret, newSecret)
	// The previous step's code, so the current step's is left unspent above it for the next sign-in.
	enrolmentCode := otptest.PreviousStepCode(t, newSecret)
	resp = passSetupRecoveryCodes(t, httpClient, authenticateWithOtp(t, httpClient, otpUrl, otpPage, enrolmentCode))
	_ = otpPage.Body.Close()
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()

	stored, err = database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.True(t, stored.OTPEnabled)
	assert.Zero(t, stored.OtpConsecutiveFailures, "the new authenticator starts with no failures against it")
	assert.False(t, adminUser(t, adminToken, user.Id).OTPAuthenticatorDisabled)

	// And the new authenticator's code verifies at the next sign-in.
	httpClient, otpPage, otpUrl = startOtpCeremony(t, client, redirectUri, user, newPassword, "")
	resp = authenticateWithOtp(t, httpClient, otpUrl, otpPage, currentStepCode(t, newSecret, enrolmentCode))
	_ = otpPage.Body.Close()
	assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
}

// assertPasswordRefusedAt asserts that a fresh browser signing in to client with password is answered
// "Authentication failed." at /auth/pwd.
func assertPasswordRefusedAt(t *testing.T, client *record.Client, redirectUri *record.RedirectURI,
	user *record.User, password string) {
	t.Helper()

	httpClient := createHttpClient(t)
	resp, err := httpClient.Get(appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code&code_challenge_method=S256&code_challenge=" + fake.LetterN(43) +
		"&scope=openid&state=" + fake.LetterN(8) + "&nonce=" + fake.LetterN(8))
	require.NoError(t, err)
	location := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, location)
	location = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	pwdPage := loadPage(t, httpClient, location)
	resp = authenticateWithPassword(t, httpClient, location, pwdPage, user.Email, password)
	_ = pwdPage.Body.Close()
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode, "the password form is shown again, not passed")
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "Authentication failed.", strings.TrimSpace(doc.Find(`[role="alert"]`).Text()))
}

// wrongCodeBeside returns a six-digit code that is not code.
func wrongCodeBeside(code string) string {
	digits := []byte(code)
	digits[0] = '0' + (digits[0]-'0'+1)%10
	return string(digits)
}

// adminUser reads a user through the admin API, as the admin console does.
func adminUser(t *testing.T, adminToken string, userId int64) api.UserResponse {
	t.Helper()

	resp, _ := sendAdmin(t, adminToken, http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d", userId), nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got api.GetUserResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	return got.User
}

// disabledEventsFor counts the otp_authenticator_disabled entries naming the user.
func disabledEventsFor(t *testing.T, adminToken string, userId int64) int {
	t.Helper()

	logs, resp := getAuditLogs(t, adminToken, "auditEvent="+audit.EventOTPAuthenticatorDisabled+"&size=200")
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	count := 0
	for _, entry := range logs.AuditLogs {
		var details map[string]any
		require.NoError(t, json.Unmarshal([]byte(entry.Details), &details))
		if id, ok := details["user_id"].(float64); ok && int64(id) == userId {
			count++
		}
	}
	return count
}
