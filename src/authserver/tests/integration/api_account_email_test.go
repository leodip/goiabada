package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getUserAccessTokenWithAccountScope_Email(t *testing.T) (string, *models.User) {
	scope := "openid profile email " + constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	return createUserAccessTokenWithScope(t, scope)
}

// accountEmailPassword is the password every user in this file is given, since the email change
// requires it (#404).
const accountEmailPassword = "Corr3ct!Pass"

// givePassword sets a user's password through the narrow write, so nothing else the fixture
// stored is written back.
func givePassword(t *testing.T, user *models.User, password string) {
	t.Helper()
	hash, err := passwordhash.Hash(password)
	require.NoError(t, err)
	require.NoError(t, database.SetUserPasswordHash(context.Background(), nil, user.Id, hash))
}

// accountEmailUserWithPassword is a user holding an account-scoped token and a known password.
func accountEmailUserWithPassword(t *testing.T) (string, *models.User) {
	t.Helper()
	accessToken, user := getUserAccessTokenWithAccountScope_Email(t)
	givePassword(t, user, accountEmailPassword)
	return accessToken, user
}

func TestAPIAccountEmailPut_Success(t *testing.T) {
	accessToken, u := accountEmailUserWithPassword(t)

	// New random email (<= 60 chars total)
	local := strings.ToLower(fake.LetterN(8))
	newEmail := local + "@example.com"

	url := appConfig.AuthServer.BaseURL + "/api/v1/account/email"
	resp := makeAPIRequest(t, "PUT", url, accessToken,
		api.UpdateAccountEmailRequest{Email: newEmail, CurrentPassword: accountEmailPassword})
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d. body: %s", resp.StatusCode, string(body))
	}
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var updateResp api.UpdateUserResponse
	err := json.NewDecoder(resp.Body).Decode(&updateResp)
	assert.NoError(t, err)
	assert.Equal(t, u.Id, updateResp.User.Id)
	assert.Equal(t, newEmail, updateResp.User.Email)
	assert.False(t, updateResp.User.EmailVerified)

	// Verify persisted changes
	updatedUser, err := database.GetUserById(context.Background(), nil, u.Id)
	assert.NoError(t, err)
	assert.NotNil(t, updatedUser)
	assert.Equal(t, newEmail, updatedUser.Email)
	assert.False(t, updatedUser.EmailVerified)
	assert.Nil(t, updatedUser.EmailVerificationCodeEncrypted)
	assert.False(t, updatedUser.EmailVerificationCodeIssuedAt.Valid)
}

func TestAPIAccountEmailPut_ValidationErrors(t *testing.T) {
	accessToken, _ := accountEmailUserWithPassword(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/account/email"

	// Empty email
	resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountEmailRequest{Email: "", CurrentPassword: accountEmailPassword})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "Please enter an email address.", err1.ErrorDescription)

	// Invalid format
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountEmailRequest{Email: "invalid-email", CurrentPassword: accountEmailPassword})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "Please enter a valid email address.", err2.ErrorDescription)

	// Too long (> 60 chars)
	longLocal := strings.Repeat("a", 49)     // 49 + 1 + 10 = 60; use 50 to exceed
	longEmail := longLocal + "1@example.com" // 50 + 1 + 10 = 61
	resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountEmailRequest{Email: longEmail, CurrentPassword: accountEmailPassword})
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	var err3 api.ErrorResponse
	_ = json.NewDecoder(resp3.Body).Decode(&err3)
	assert.Equal(t, "The email address cannot exceed a maximum length of 60 characters.", err3.ErrorDescription)
}

func TestAPIAccountEmailPut_EmailAlreadyExists(t *testing.T) {
	accessToken, _ := accountEmailUserWithPassword(t)

	// Create another user with a known email
	otherEmail := "existing_" + strings.ToLower(fake.LetterN(6)) + "@example.com"
	otherUser := &models.User{Email: otherEmail, Enabled: true, Subject: fake.UUID()}
	err := database.CreateUser(context.Background(), nil, otherUser)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteUser(context.Background(), nil, otherUser.Id) }()

	url := appConfig.AuthServer.BaseURL + "/api/v1/account/email"
	resp := makeAPIRequest(t, "PUT", url, accessToken,
		api.UpdateAccountEmailRequest{Email: otherEmail, CurrentPassword: accountEmailPassword})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Apologies, but this email address is already registered.", errResp.ErrorDescription)
}

func TestAPIAccountEmailPut_UnauthorizedAndScope(t *testing.T) {
	url := appConfig.AuthServer.BaseURL + "/api/v1/account/email"

	// No token
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	body1, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.Contains(t, string(body1), "Access token required.")

	// Insufficient scope (a client-credentials token whose scope no route grants)
	tok := createClientCredentialsTokenWithoutRouteScope(t)
	resp2 := makeAPIRequest(t, "PUT", url, tok, api.UpdateAccountEmailRequest{Email: "a@example.com"})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(body2), "Insufficient scope.")
}

func TestAPIAccountEmailPut_InvalidRequestBody(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope_Email(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/account/email"

	// Invalid JSON (no body)
	req, err := http.NewRequest("PUT", url, nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var errResp api.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&errResp)
	assert.Equal(t, "Invalid request body", errResp.ErrorDescription)
}

// TestAPIAccountEmailPut_AWrongPasswordIsRefusedAndChangesNothing is #404 decision 3, over real
// HTTP: a wrong password is refused 400 AUTHENTICATION_FAILED before the address is looked at, so
// an address another account holds gets the same answer as a free one, and the row is unchanged.
func TestAPIAccountEmailPut_AWrongPasswordIsRefusedAndChangesNothing(t *testing.T) {
	accessToken, u := accountEmailUserWithPassword(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/account/email"

	otherEmail := "existing_" + strings.ToLower(fake.LetterN(6)) + "@example.com"
	otherUser := &models.User{Email: otherEmail, Enabled: true, Subject: fake.UUID()}
	require.NoError(t, database.CreateUser(context.Background(), nil, otherUser))
	defer func() { _ = database.DeleteUser(context.Background(), nil, otherUser.Id) }()

	for _, address := range []string{strings.ToLower(fake.LetterN(8)) + "@example.com", otherEmail, "invalid-email"} {
		resp := makeAPIRequest(t, "PUT", url, accessToken,
			api.UpdateAccountEmailRequest{Email: address, CurrentPassword: "Wr0ng!Pass"})
		var errResp api.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, address)
		assert.Equal(t, "AUTHENTICATION_FAILED", errResp.ErrorCode, address)
		assert.Equal(t, "Authentication failed. Check your current password and try again.", errResp.ErrorDescription, address)
	}

	persisted, err := database.GetUserById(context.Background(), nil, u.Id)
	require.NoError(t, err)
	assert.Equal(t, u.Email, persisted.Email, "a refused change writes nothing")
}

// TestAPIAccountEmailPut_ABlankPasswordIsAValidationError is #404 decision 3: a request that
// carries no password is refused 400 VALIDATION_ERROR, which is the breaking change to the wire
// contract a caller sending the old body meets.
func TestAPIAccountEmailPut_ABlankPasswordIsAValidationError(t *testing.T) {
	accessToken, u := accountEmailUserWithPassword(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/account/email"

	for _, body := range []interface{}{
		map[string]string{"email": strings.ToLower(fake.LetterN(8)) + "@example.com"},
		api.UpdateAccountEmailRequest{Email: strings.ToLower(fake.LetterN(8)) + "@example.com", CurrentPassword: "  "},
	} {
		resp := makeAPIRequest(t, "PUT", url, accessToken, body)
		var errResp api.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, "VALIDATION_ERROR", errResp.ErrorCode)
		assert.Equal(t, "Current password is required.", errResp.ErrorDescription)
	}

	persisted, err := database.GetUserById(context.Background(), nil, u.Id)
	require.NoError(t, err)
	assert.Equal(t, u.Email, persisted.Email, "a refused change writes nothing")
}

// TestAPIAccountEmailPut_ResubmittingTheCurrentAddressKeepsItVerified is #404 decision 10: the
// address the account already has, in any case and with surrounding spaces, answers 200 with the
// user as stored and writes nothing, so the verified flag survives.
func TestAPIAccountEmailPut_ResubmittingTheCurrentAddressKeepsItVerified(t *testing.T) {
	accessToken, u := accountEmailUserWithPassword(t)
	verified, err := database.GetUserById(context.Background(), nil, u.Id)
	require.NoError(t, err)
	verified.EmailVerified = true
	require.NoError(t, database.UpdateUser(context.Background(), nil, verified))
	before, err := database.GetUserById(context.Background(), nil, u.Id)
	require.NoError(t, err)
	require.True(t, before.EmailVerified)

	url := appConfig.AuthServer.BaseURL + "/api/v1/account/email"
	resp := makeAPIRequest(t, "PUT", url, accessToken,
		api.UpdateAccountEmailRequest{Email: "  " + strings.ToUpper(before.Email) + " ", CurrentPassword: accountEmailPassword})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var updateResp api.UpdateUserResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&updateResp))
	assert.Equal(t, before.Email, updateResp.User.Email)
	assert.True(t, updateResp.User.EmailVerified)

	after, err := database.GetUserById(context.Background(), nil, u.Id)
	require.NoError(t, err)
	assert.Equal(t, before.Email, after.Email)
	assert.True(t, after.EmailVerified, "re-saving the address must not clear its verified flag")
	assert.Equal(t, before.UpdatedAt, after.UpdatedAt, "nothing was written")
}
