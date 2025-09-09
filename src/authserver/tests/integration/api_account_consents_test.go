package integrationtests

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "strings"
    "testing"
    "time"

    "github.com/google/uuid"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/models"
    "github.com/stretchr/testify/assert"
)

func TestAPIAccountConsentsGet_Success(t *testing.T) {
    accessToken, u := getUserAccessTokenWithAccountScope(t)

    // Create a client and a consent for this user
    client := &models.Client{
        ClientIdentifier: "acct-consents-client-" + uuid.New().String()[:8],
        Description:      "Account Consents Test Client",
        Enabled:          true,
        IsPublic:         true,
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    consent := &models.UserConsent{
        UserId:    u.Id,
        ClientId:  client.Id,
        Scope:     "openid profile email",
        GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
    }
    err = database.CreateUserConsent(nil, consent)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUserConsent(nil, consent.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/account/consents"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var getResp api.GetUserConsentsResponse
    err = json.NewDecoder(resp.Body).Decode(&getResp)
    assert.NoError(t, err)
    assert.NotNil(t, getResp.Consents)
    assert.GreaterOrEqual(t, len(getResp.Consents), 1)

    // Find our consent and assert fields
    var found *api.UserConsentResponse
    for i := range getResp.Consents {
        if getResp.Consents[i].Id == consent.Id {
            found = &getResp.Consents[i]
            break
        }
    }
    if found == nil {
        t.Fatalf("expected to find consent id %d in response", consent.Id)
    }
    assert.Equal(t, u.Id, found.UserId)
    assert.Equal(t, client.Id, found.ClientId)
    assert.Equal(t, consent.Scope, found.Scope)
    assert.Equal(t, client.ClientIdentifier, found.ClientIdentifier)
    assert.Equal(t, client.Description, found.ClientDescription)
}

func TestAPIAccountConsentsGet_UnauthorizedAndScope(t *testing.T) {
    url := config.GetAuthServer().BaseURL + "/api/v1/account/consents"

    // No token
    req, err := http.NewRequest("GET", url, nil)
    assert.NoError(t, err)
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
    body1, _ := io.ReadAll(resp.Body)
    assert.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
    assert.Equal(t, "Access token required", strings.TrimSpace(string(body1)))

    // Invalid token
    resp2 := makeAPIRequest(t, "GET", url, "invalid-token", nil)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
    body2, _ := io.ReadAll(resp2.Body)
    assert.Equal(t, "Access token required", strings.TrimSpace(string(body2)))

    // Insufficient scope (use userinfo scope via client-credentials)
    tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
    resp3 := makeAPIRequest(t, "GET", url, tok, nil)
    defer resp3.Body.Close()
    assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
    body3, _ := io.ReadAll(resp3.Body)
    assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body3)))
}

func TestAPIAccountConsentDelete_Success(t *testing.T) {
    accessToken, u := getUserAccessTokenWithAccountScope(t)

    // Create a client and consent for this user
    client := &models.Client{
        ClientIdentifier: "acct-consents-del-client-" + uuid.New().String()[:8],
        Description:      "Account Consents Delete Client",
        Enabled:          true,
        IsPublic:         true,
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    consent := &models.UserConsent{
        UserId:    u.Id,
        ClientId:  client.Id,
        Scope:     "openid profile",
        GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
    }
    err = database.CreateUserConsent(nil, consent)
    assert.NoError(t, err)

    url := config.GetAuthServer().BaseURL + "/api/v1/account/consents/" + fmt.Sprintf("%d", consent.Id)
    resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var delResp api.SuccessResponse
    err = json.NewDecoder(resp.Body).Decode(&delResp)
    assert.NoError(t, err)
    assert.True(t, delResp.Success)

    // Confirm deletion
    got, err := database.GetUserConsentById(nil, consent.Id)
    assert.NoError(t, err)
    assert.Nil(t, got)
}

func TestAPIAccountConsentDelete_ForbiddenOnOtherUser(t *testing.T) {
    // Create token for user1
    accessToken, user1 := getUserAccessTokenWithAccountScope(t)

    // Create another user (user2)
    user2 := &models.User{
        Subject:    uuid.New(),
        Enabled:    true,
        Email:      "otheruser@consents.test",
        GivenName:  "Other",
        FamilyName: "User",
    }
    err := database.CreateUser(nil, user2)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUser(nil, user2.Id) }()

    // Create client and consent for user2
    client := &models.Client{
        ClientIdentifier: "acct-consents-oth-client-" + uuid.New().String()[:8],
        Description:      "Other User Client",
        Enabled:          true,
        IsPublic:         true,
    }
    err = database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    consent := &models.UserConsent{
        UserId:    user2.Id,
        ClientId:  client.Id,
        Scope:     "openid",
        GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
    }
    err = database.CreateUserConsent(nil, consent)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUserConsent(nil, consent.Id) }()

    // Attempt to delete using user1 token
    url := config.GetAuthServer().BaseURL + "/api/v1/account/consents/" + fmt.Sprintf("%d", consent.Id)
    resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusForbidden, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Forbidden", errResp.Error.Message)
    assert.Equal(t, "FORBIDDEN", errResp.Error.Code)

    // Ensure consent still exists
    got, err := database.GetUserConsentById(nil, consent.Id)
    assert.NoError(t, err)
    assert.NotNil(t, got)

    // Sanity check user ids differ
    assert.NotEqual(t, user1.Id, user2.Id)
}

func TestAPIAccountConsentDelete_NotFoundAndBadId(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope(t)

    // Not found
    urlNF := config.GetAuthServer().BaseURL + "/api/v1/account/consents/999999999"
    respNF := makeAPIRequest(t, "DELETE", urlNF, accessToken, nil)
    defer respNF.Body.Close()
    assert.Equal(t, http.StatusNotFound, respNF.StatusCode)
    var errNF api.ErrorResponse
    _ = json.NewDecoder(respNF.Body).Decode(&errNF)
    assert.Equal(t, "Consent not found", errNF.Error.Message)
    assert.Equal(t, "NOT_FOUND", errNF.Error.Code)

    // Bad id format
    urlBad := config.GetAuthServer().BaseURL + "/api/v1/account/consents/abc"
    respBad := makeAPIRequest(t, "DELETE", urlBad, accessToken, nil)
    defer respBad.Body.Close()
    assert.Equal(t, http.StatusBadRequest, respBad.StatusCode)
    var errBad api.ErrorResponse
    _ = json.NewDecoder(respBad.Body).Decode(&errBad)
    assert.Equal(t, "Invalid consent ID format", errBad.Error.Message)
    assert.Equal(t, "VALIDATION_ERROR", errBad.Error.Code)
}
