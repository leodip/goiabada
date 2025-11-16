package integrationtests

import (
    "encoding/json"
    "io"
    "net/http"
    "strings"
    "testing"

    "github.com/brianvoe/gofakeit/v6"
    "github.com/google/uuid"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/models"
    "github.com/stretchr/testify/assert"
)

func getUserAccessTokenWithAccountScope_Email(t *testing.T) (string, *models.User) {
    scope := "openid profile email " + constants.AdminConsoleResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
    return createUserAccessTokenWithScope(t, scope)
}

func TestAPIAccountEmailPut_Success(t *testing.T) {
    accessToken, u := getUserAccessTokenWithAccountScope_Email(t)

    // New random email (<= 60 chars total)
    local := strings.ToLower(gofakeit.LetterN(8))
    newEmail := local + "@example.com"

    url := config.GetAuthServer().BaseURL + "/api/v1/account/email"
    resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountEmailRequest{Email: newEmail})
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
    updatedUser, err := database.GetUserById(nil, u.Id)
    assert.NoError(t, err)
    assert.NotNil(t, updatedUser)
    assert.Equal(t, newEmail, updatedUser.Email)
    assert.False(t, updatedUser.EmailVerified)
    assert.Nil(t, updatedUser.EmailVerificationCodeEncrypted)
    assert.False(t, updatedUser.EmailVerificationCodeIssuedAt.Valid)
}

func TestAPIAccountEmailPut_ValidationErrors(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope_Email(t)
    url := config.GetAuthServer().BaseURL + "/api/v1/account/email"

    // Empty email
    resp1 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountEmailRequest{Email: ""})
    defer func() { _ = resp1.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
    var err1 api.ErrorResponse
    _ = json.NewDecoder(resp1.Body).Decode(&err1)
    assert.Equal(t, "Please enter an email address.", err1.Error.Message)

    // Invalid format
    resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountEmailRequest{Email: "invalid-email"})
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var err2 api.ErrorResponse
    _ = json.NewDecoder(resp2.Body).Decode(&err2)
    assert.Equal(t, "Please enter a valid email address.", err2.Error.Message)

    // Too long (> 60 chars)
    longLocal := strings.Repeat("a", 49) // 49 + 1 + 10 = 60; use 50 to exceed
    longEmail := longLocal + "1@example.com" // 50 + 1 + 10 = 61
    resp3 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountEmailRequest{Email: longEmail})
    defer func() { _ = resp3.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
    var err3 api.ErrorResponse
    _ = json.NewDecoder(resp3.Body).Decode(&err3)
    assert.Equal(t, "The email address cannot exceed a maximum length of 60 characters.", err3.Error.Message)
}

func TestAPIAccountEmailPut_EmailAlreadyExists(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope_Email(t)

    // Create another user with a known email
    otherEmail := "existing_" + strings.ToLower(gofakeit.LetterN(6)) + "@example.com"
    otherUser := &models.User{Email: otherEmail, Enabled: true, Subject: uuid.New()}
    err := database.CreateUser(nil, otherUser)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUser(nil, otherUser.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/account/email"
    resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateAccountEmailRequest{Email: otherEmail})
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Apologies, but this email address is already registered.", errResp.Error.Message)
}

func TestAPIAccountEmailPut_UnauthorizedAndScope(t *testing.T) {
    url := config.GetAuthServer().BaseURL + "/api/v1/account/email"

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

    // Insufficient scope (authserver:userinfo via client credentials)
    tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
    resp2 := makeAPIRequest(t, "PUT", url, tok, api.UpdateAccountEmailRequest{Email: "a@example.com"})
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
    body2, _ := io.ReadAll(resp2.Body)
    assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body2)))
}

func TestAPIAccountEmailPut_InvalidRequestBody(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope_Email(t)
    url := config.GetAuthServer().BaseURL + "/api/v1/account/email"

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
    assert.Equal(t, "Invalid request body", errResp.Error.Message)
}
