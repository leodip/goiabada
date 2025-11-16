package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// helper to set a user's password to a known value
func setUserPassword(t *testing.T, user *models.User, newPassword string) {
	t.Helper()
	hash, err := hashutil.HashPassword(newPassword)
	assert.NoError(t, err)
	user.PasswordHash = hash
	err = database.UpdateUser(nil, user)
	assert.NoError(t, err)
}

func TestAPIAccountPasswordPut_Success(t *testing.T) {
	// Acquire access token with account scope and the user entity
	accessToken, u := getUserAccessTokenWithAccountScope(t)

	// Set a known current password for the user
	current := "OldPass1!"
	setUserPassword(t, u, current)

	// Prepare request
	reqBody := api.UpdateAccountPasswordRequest{
		CurrentPassword: current,
		NewPassword:     "NewPass2$",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/account/password"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	// Expect success
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	// Parse response
	var updateResp api.UpdateUserResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResp)
	assert.NoError(t, err)
	assert.Equal(t, u.Id, updateResp.User.Id)

	// Verify password updated in DB and matches
	updatedUser, err := database.GetUserById(nil, u.Id)
	assert.NoError(t, err)
	assert.True(t, hashutil.VerifyPasswordHash(updatedUser.PasswordHash, reqBody.NewPassword))
}

func TestAPIAccountPasswordPut_WrongCurrentPassword(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope(t)

	setUserPassword(t, u, "Correct1!")

	reqBody := api.UpdateAccountPasswordRequest{
		CurrentPassword: "WrongPwd1!",
		NewPassword:     "NewPass2$",
	}

	url := config.GetAuthServer().BaseURL + "/api/v1/account/password"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Authentication failed. Check your current password and try again.", errResp.Error.Message)
}

func TestAPIAccountPasswordPut_ValidationErrors(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope(t)
	setUserPassword(t, u, "Correct1!")

	url := config.GetAuthServer().BaseURL + "/api/v1/account/password"

	// Missing current password
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountPasswordRequest{CurrentPassword: "", NewPassword: "NewPass2$"})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "Current password is required.", err1.Error.Message)

	// Missing new password
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountPasswordRequest{CurrentPassword: "Correct1!", NewPassword: ""})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "New password is required.", err2.Error.Message)

	// Too short per default policy (low => min 6)
	resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountPasswordRequest{CurrentPassword: "Correct1!", NewPassword: "123"})
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	var err3 api.ErrorResponse
	_ = json.NewDecoder(resp3.Body).Decode(&err3)
	assert.Equal(t, "The minimum length for the password is 6 characters", err3.Error.Message)
}

func TestAPIAccountPasswordPut_UnauthorizedAndScope(t *testing.T) {
	url := config.GetAuthServer().BaseURL + "/api/v1/account/password"

	// No token
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body1, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "Access token required", strings.TrimSpace(string(body1)))

	// Invalid token
	resp2 := makeAPIRequest(t, "PUT", url, "invalid-token", api.UpdateAccountPasswordRequest{CurrentPassword: "a", NewPassword: "b"})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	assert.Equal(t, "Access token required", strings.TrimSpace(string(body2)))

	// Insufficient scope: use client-credentials with userinfo scope
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp3 := makeAPIRequest(t, "PUT", url, tok, api.UpdateAccountPasswordRequest{CurrentPassword: "a", NewPassword: "b"})
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
	body3, _ := io.ReadAll(resp3.Body)
	assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body3)))
}

func TestAPIAccountPasswordPut_InvalidRequestBody(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)
	url := config.GetAuthServer().BaseURL + "/api/v1/account/password"

	// No JSON body
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
