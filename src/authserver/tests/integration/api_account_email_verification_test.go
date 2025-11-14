package integrationtests

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func getUserAccessTokenWithAccountScope_EmailVerification(t *testing.T) (string, *models.User) {
	return getUserAccessTokenWithAccountScope_Email(t)
}

// POST /api/v1/account/email/verification/send
func TestAPIAccountEmailVerificationSend_Success(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope_EmailVerification(t)

	// Ensure SMTP enabled
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	prevSMTP := settings.SMTPEnabled
	settings.SMTPEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() {
		settings.SMTPEnabled = prevSMTP
		_ = database.UpdateSettings(nil, settings)
	}()

	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification/send"
	resp := makeAPIRequest(t, "POST", url, accessToken, map[string]string{})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Logf("Request failed with status %d, body: %s", resp.StatusCode, string(bodyBytes))
	}
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.AccountEmailVerificationSendResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)
	assert.True(t, body.EmailVerificationSent)
	assert.False(t, body.TooManyRequests)
	assert.False(t, body.EmailVerified)
	assert.Equal(t, u.Email, body.EmailDestination)

	// DB should have code and issuedAt
	updated, err := database.GetUserById(nil, u.Id)
	assert.NoError(t, err)
	assert.NotNil(t, updated.EmailVerificationCodeEncrypted)
	assert.True(t, updated.EmailVerificationCodeIssuedAt.Valid)
	assert.WithinDuration(t, time.Now().UTC(), updated.EmailVerificationCodeIssuedAt.Time, 3*time.Second)
}

func TestAPIAccountEmailVerificationSend_TooManyRequests(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope_EmailVerification(t)

	// Ensure SMTP enabled
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	prevSMTP := settings.SMTPEnabled
	settings.SMTPEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() { settings.SMTPEnabled = prevSMTP; _ = database.UpdateSettings(nil, settings) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification/send"
	// First send
	resp1 := makeAPIRequest(t, "POST", url, accessToken, map[string]string{})
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp1.Body)
		t.Logf("First request failed with status %d, body: %s", resp1.StatusCode, string(bodyBytes))
	}
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Immediate resend should be rate-limited
	resp2 := makeAPIRequest(t, "POST", url, accessToken, map[string]string{})
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var body api.AccountEmailVerificationSendResponse
	err = json.NewDecoder(resp2.Body).Decode(&body)
	assert.NoError(t, err)
	assert.True(t, body.TooManyRequests)
	assert.Greater(t, body.WaitInSeconds, 0)
}

func TestAPIAccountEmailVerificationSend_AlreadyVerified(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope_EmailVerification(t)

	// Enable SMTP
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	prevSMTP := settings.SMTPEnabled
	settings.SMTPEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() { settings.SMTPEnabled = prevSMTP; _ = database.UpdateSettings(nil, settings) }()

	// Mark user as verified
	user, err := database.GetUserById(nil, u.Id)
	assert.NoError(t, err)
	user.EmailVerified = true
	user.EmailVerificationCodeEncrypted = nil
	user.EmailVerificationCodeIssuedAt = sqlNullTimeFalse()
	err = database.UpdateUser(nil, user)
	assert.NoError(t, err)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification/send"
	resp := makeAPIRequest(t, "POST", url, accessToken, map[string]string{})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.AccountEmailVerificationSendResponse
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.True(t, body.EmailVerified)
	assert.False(t, body.EmailVerificationSent)
}

func TestAPIAccountEmailVerificationSend_SMTPDisabled(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope_EmailVerification(t)

	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	prev := settings.SMTPEnabled
	settings.SMTPEnabled = false
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() { settings.SMTPEnabled = prev; _ = database.UpdateSettings(nil, settings) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification/send"
	resp := makeAPIRequest(t, "POST", url, accessToken, map[string]string{})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "SMTP is not enabled", errResp.Error.Message)
	assert.Equal(t, "SMTP_NOT_ENABLED", errResp.Error.Code)
}

func TestAPIAccountEmailVerificationSend_Unauthorized(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification/send"
	req, err := http.NewRequest("POST", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	b, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "Access token required", strings.TrimSpace(string(b)))
}

// POST /api/v1/account/email/verification
func TestAPIAccountEmailVerification_VerifySuccess(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope_EmailVerification(t)

	// Ensure SMTP enabled
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	prevSMTP := settings.SMTPEnabled
	settings.SMTPEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() { settings.SMTPEnabled = prevSMTP; _ = database.UpdateSettings(nil, settings) }()

	// Trigger send to generate code
	sendURL := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification/send"
	_ = makeAPIRequest(t, "POST", sendURL, accessToken, map[string]string{})

	// Load user and decrypt code
	user, err := database.GetUserById(nil, u.Id)
	assert.NoError(t, err)
	code, err := encryption.DecryptText(user.EmailVerificationCodeEncrypted, settings.AESEncryptionKey)
	assert.NoError(t, err)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification"
	resp := makeAPIRequest(t, "POST", url, accessToken, api.VerifyAccountEmailRequest{VerificationCode: code})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body api.UpdateUserResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)
	assert.True(t, body.User.EmailVerified)

	updated, err := database.GetUserById(nil, u.Id)
	assert.NoError(t, err)
	assert.True(t, updated.EmailVerified)
	assert.Nil(t, updated.EmailVerificationCodeEncrypted)
	assert.False(t, updated.EmailVerificationCodeIssuedAt.Valid)
}

func TestAPIAccountEmailVerification_VerifyInvalidCode(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope_EmailVerification(t)

	// Ensure SMTP enabled
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	prevSMTP := settings.SMTPEnabled
	settings.SMTPEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() { settings.SMTPEnabled = prevSMTP; _ = database.UpdateSettings(nil, settings) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification"
	resp := makeAPIRequest(t, "POST", url, accessToken, api.VerifyAccountEmailRequest{VerificationCode: "WRONG"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Invalid or expired verification code", errResp.Error.Message)
	assert.Equal(t, "INVALID_OR_EXPIRED_VERIFICATION_CODE", errResp.Error.Code)
}

func TestAPIAccountEmailVerification_VerifyExpiredCode(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope_EmailVerification(t)

	// Ensure SMTP enabled
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	prevSMTP := settings.SMTPEnabled
	settings.SMTPEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() { settings.SMTPEnabled = prevSMTP; _ = database.UpdateSettings(nil, settings) }()

	// Manually set a code that is already expired
	user, err := database.GetUserById(nil, u.Id)
	assert.NoError(t, err)
	codePlain := "ABC123"
	encrypted, err := encryption.EncryptText(codePlain, settings.AESEncryptionKey)
	assert.NoError(t, err)
	user.EmailVerificationCodeEncrypted = encrypted
	user.EmailVerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC().Add(-6 * time.Minute), Valid: true}
	err = database.UpdateUser(nil, user)
	assert.NoError(t, err)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification"
	resp := makeAPIRequest(t, "POST", url, accessToken, api.VerifyAccountEmailRequest{VerificationCode: codePlain})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Invalid or expired verification code", errResp.Error.Message)
}

func TestAPIAccountEmailVerification_VerifyAlreadyVerified(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope_EmailVerification(t)

	// Enable SMTP
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	prevSMTP := settings.SMTPEnabled
	settings.SMTPEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() { settings.SMTPEnabled = prevSMTP; _ = database.UpdateSettings(nil, settings) }()

	user, err := database.GetUserById(nil, u.Id)
	assert.NoError(t, err)
	user.EmailVerified = true
	user.EmailVerificationCodeEncrypted = nil
	user.EmailVerificationCodeIssuedAt = sqlNullTimeFalse()
	err = database.UpdateUser(nil, user)
	assert.NoError(t, err)

	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification"
	resp := makeAPIRequest(t, "POST", url, accessToken, api.VerifyAccountEmailRequest{VerificationCode: "ANY"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.UpdateUserResponse
	_ = json.NewDecoder(resp.Body).Decode(&body)
	assert.True(t, body.User.EmailVerified)
}

func TestAPIAccountEmailVerification_VerifySMTPDisabled(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope_EmailVerification(t)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	prev := settings.SMTPEnabled
	settings.SMTPEnabled = false
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() { settings.SMTPEnabled = prev; _ = database.UpdateSettings(nil, settings) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification"
	resp := makeAPIRequest(t, "POST", url, accessToken, api.VerifyAccountEmailRequest{VerificationCode: "ABC123"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "SMTP is not enabled", errResp.Error.Message)
	assert.Equal(t, "SMTP_NOT_ENABLED", errResp.Error.Code)
}

func TestAPIAccountEmailVerification_VerifyInvalidRequestBody(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope_EmailVerification(t)

	// Enable SMTP
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	prevSMTP := settings.SMTPEnabled
	settings.SMTPEnabled = true
	err = database.UpdateSettings(nil, settings)
	assert.NoError(t, err)
	defer func() { settings.SMTPEnabled = prevSMTP; _ = database.UpdateSettings(nil, settings) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification"
	req, err := http.NewRequest("POST", url, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Invalid request body", errResp.Error.Message)
}

func TestAPIAccountEmailVerification_VerifyUnauthorized(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/email/verification"
	req, err := http.NewRequest("POST", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	b, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "Access token required", strings.TrimSpace(string(b)))
}

// helpers for sql.NullTime construction
func sqlNullTimeFalse() sql.NullTime { return sql.NullTime{Valid: false} }
