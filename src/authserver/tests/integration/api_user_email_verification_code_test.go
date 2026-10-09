package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIUserEmailVerificationCodePost_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	user := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("email-code-user@example.test"),
		GivenName:     "Email",
		FamilyName:    "Code",
		EmailVerified: false,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, user.Id)
	}()

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.GenerateUserEmailVerificationCodeResponse
	err := json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	assert.NotEmpty(t, body.VerificationCode)
	assert.NotNil(t, body.VerificationCodeExpiresAt)
	assert.Equal(t, user.Id, body.UserId)
	assert.Equal(t, user.Email, body.Email)
	assert.WithinDuration(t, time.Now().UTC().Add(5*time.Minute), *body.VerificationCodeExpiresAt, 5*time.Second)

	updatedUser, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.NotNil(t, updatedUser.EmailVerificationCodeEncrypted)
	assert.True(t, updatedUser.EmailVerificationCodeIssuedAt.Valid)
	assert.False(t, updatedUser.EmailVerified)
	assert.WithinDuration(t, time.Now().UTC(), updatedUser.EmailVerificationCodeIssuedAt.Time, 3*time.Second)

	decrypted, err := dataCipher.Decrypt(updatedUser.EmailVerificationCodeEncrypted)
	require.NoError(t, err)
	assert.Equal(t, body.VerificationCode, decrypted)
}

func TestAPIUserEmailVerificationCodePost_VerifiedUser(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	user := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("verified-email-code@example.test"),
		GivenName:     "Verified",
		FamilyName:    "User",
		EmailVerified: true,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, user.Id)
	}()

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body api.GenerateUserEmailVerificationCodeResponse
	err := json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	assert.NotEmpty(t, body.VerificationCode)
	assert.Equal(t, user.Id, body.UserId)
	assert.Equal(t, user.Email, body.Email)

	updatedUser, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.NotNil(t, updatedUser.EmailVerificationCodeEncrypted)
	assert.True(t, updatedUser.EmailVerificationCodeIssuedAt.Valid)
	assert.False(t, updatedUser.EmailVerified)

	decrypted, err := dataCipher.Decrypt(updatedUser.EmailVerificationCodeEncrypted)
	require.NoError(t, err)
	assert.Equal(t, body.VerificationCode, decrypted)
}

func TestAPIUserEmailVerificationCodePost_NotFound(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/999999/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "User not found", errResp.ErrorDescription)
	assert.Equal(t, "NOT_FOUND", errResp.ErrorCode)
}

func TestAPIUserEmailVerificationCodePost_InvalidUserId(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/invalid/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Invalid user ID", errResp.ErrorDescription)
	assert.Equal(t, "VALIDATION_ERROR", errResp.ErrorCode)
}

func TestAPIUserEmailVerificationCodePost_Unauthorized(t *testing.T) {
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/1/email/verification-code"
	req, err := http.NewRequest("POST", url, nil)
	require.NoError(t, err)

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(body), "Access token required.")
}

func TestAPIUserEmailVerificationCodePost_InsufficientScope(t *testing.T) {
	token := createClientCredentialsTokenWithoutRouteScope(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/1/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, token, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(body), "Insufficient scope.")
}

func TestAPIUserEmailVerificationCodePost_InvalidToken(t *testing.T) {
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/1/email/verification-code"
	resp := makeAPIRequest(t, "POST", url, "invalid-token", nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(body), "The access token is invalid.")
}

func TestAPIUserEmailVerificationCodePost_RegeneratesCode(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	user := &record.User{
		Subject:       fake.UUID(),
		Enabled:       true,
		Email:         uniqueEmail("regen-email-code@example.test"),
		GivenName:     "Regen",
		FamilyName:    "Code",
		EmailVerified: false,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	defer func() {
		_ = database.DeleteUser(context.Background(), nil, user.Id)
	}()

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/" + strconv.FormatInt(user.Id, 10) + "/email/verification-code"

	resp1 := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	updated1, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.True(t, updated1.EmailVerificationCodeIssuedAt.Valid)
	issuedAt1 := updated1.EmailVerificationCodeIssuedAt.Time

	time.Sleep(10 * time.Millisecond)

	resp2 := makeAPIRequest(t, "POST", url, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	updated2, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	assert.True(t, updated2.EmailVerificationCodeIssuedAt.Valid)
	assert.True(t, updated2.EmailVerificationCodeIssuedAt.Time.After(issuedAt1))
}
