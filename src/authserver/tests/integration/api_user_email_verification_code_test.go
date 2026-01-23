package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func TestAPIUserEmailVerificationCodePost_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	user := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "email-code-user@example.test",
		GivenName:     "Email",
		FamilyName:    "Code",
		EmailVerified: false,
	}
	assert.NoError(t, database.CreateUser(nil, user))
	defer func() {
		_ = database.DeleteUser(nil, user.Id)
	}()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.GenerateUserEmailVerificationCodeResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)
	assert.NotEmpty(t, body.VerificationCode)
	assert.NotNil(t, body.VerificationCodeExpiresAt)
	assert.Equal(t, user.Id, body.UserId)
	assert.Equal(t, user.Email, body.Email)
	assert.WithinDuration(t, time.Now().UTC().Add(5*time.Minute), *body.VerificationCodeExpiresAt, 5*time.Second)

	updatedUser, err := database.GetUserById(nil, user.Id)
	assert.NoError(t, err)
	assert.NotNil(t, updatedUser.EmailVerificationCodeEncrypted)
	assert.True(t, updatedUser.EmailVerificationCodeIssuedAt.Valid)
	assert.False(t, updatedUser.EmailVerified)
	assert.WithinDuration(t, time.Now().UTC(), updatedUser.EmailVerificationCodeIssuedAt.Time, 3*time.Second)

	decrypted, err := encryption.DecryptText(updatedUser.EmailVerificationCodeEncrypted, settings.AESEncryptionKey)
	assert.NoError(t, err)
	assert.Equal(t, body.VerificationCode, decrypted)
}

func TestAPIUserEmailVerificationCodePost_VerifiedUser(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)

	user := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "verified-email-code@example.test",
		GivenName:     "Verified",
		FamilyName:    "User",
		EmailVerified: true,
	}
	assert.NoError(t, database.CreateUser(nil, user))
	defer func() {
		_ = database.DeleteUser(nil, user.Id)
	}()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.GenerateUserEmailVerificationCodeResponse
	err = json.NewDecoder(resp.Body).Decode(&body)
	assert.NoError(t, err)
	assert.NotEmpty(t, body.VerificationCode)
	assert.Equal(t, user.Id, body.UserId)
	assert.Equal(t, user.Email, body.Email)

	updatedUser, err := database.GetUserById(nil, user.Id)
	assert.NoError(t, err)
	assert.NotNil(t, updatedUser.EmailVerificationCodeEncrypted)
	assert.True(t, updatedUser.EmailVerificationCodeIssuedAt.Valid)
	assert.False(t, updatedUser.EmailVerified)

	decrypted, err := encryption.DecryptText(updatedUser.EmailVerificationCodeEncrypted, settings.AESEncryptionKey)
	assert.NoError(t, err)
	assert.Equal(t, body.VerificationCode, decrypted)
}

func TestAPIUserEmailVerificationCodePost_NotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/999999/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "User not found", errResp.Error.Message)
	assert.Equal(t, "USER_NOT_FOUND", errResp.Error.Code)
}

func TestAPIUserEmailVerificationCodePost_InvalidUserId(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/invalid/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Invalid user ID", errResp.Error.Message)
	assert.Equal(t, "INVALID_USER_ID", errResp.Error.Code)
}

func TestAPIUserEmailVerificationCodePost_Unauthorized(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/1/email/verification-code"
	req, err := http.NewRequest("POST", url, nil)
	assert.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "Access token required", strings.TrimSpace(string(body)))
}

func TestAPIUserEmailVerificationCodePost_InsufficientScope(t *testing.T) {
	token := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/1/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, token, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body)))
}

func TestAPIUserEmailVerificationCodePost_InvalidToken(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/1/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, "invalid-token", nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "Access token required", strings.TrimSpace(string(body)))
}

func TestAPIUserEmailVerificationCodePost_RegeneratesCode(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	user := &models.User{
		Subject:       uuid.New(),
		Enabled:       true,
		Email:         "regen-email-code@example.test",
		GivenName:     "Regen",
		FamilyName:    "Code",
		EmailVerified: false,
	}
	assert.NoError(t, database.CreateUser(nil, user))
	defer func() {
		_ = database.DeleteUser(nil, user.Id)
	}()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/email/verification-code"

	resp1 := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	updated1, err := database.GetUserById(nil, user.Id)
	assert.NoError(t, err)
	assert.True(t, updated1.EmailVerificationCodeIssuedAt.Valid)
	issuedAt1 := updated1.EmailVerificationCodeIssuedAt.Time

	time.Sleep(10 * time.Millisecond)

	resp2 := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	updated2, err := database.GetUserById(nil, user.Id)
	assert.NoError(t, err)
	assert.True(t, updated2.EmailVerificationCodeIssuedAt.Valid)
	assert.True(t, updated2.EmailVerificationCodeIssuedAt.Time.After(issuedAt1))
}
