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
    "github.com/leodip/goiabada/core/models"
    "github.com/stretchr/testify/assert"
)

// GET /api/v1/account/sessions — happy path, includes isCurrent
func TestAPIAccountSessionsGet_Success_IncludesIsCurrent(t *testing.T) {
    accessToken, user := getUserAccessTokenWithAccountScope(t)

    // Create an extra client and a couple of sessions linked to it for richer output
    testClient := &models.Client{
        ClientIdentifier:         "acct-sess-client-" + uuid.New().String()[:8],
        ClientSecretEncrypted:    []byte("encrypted-secret"),
        Description:              "Account Sessions Client",
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 false,
        AuthorizationCodeEnabled: true,
        ClientCredentialsEnabled: false,
    }
    err := database.CreateClient(nil, testClient)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

    s1 := createTestUserSession(t, user.Id, uuid.New().String())
    s2 := createTestUserSession(t, user.Id, uuid.New().String())
    defer func() {
        _ = database.DeleteUserSession(nil, s1.Id)
        _ = database.DeleteUserSession(nil, s2.Id)
    }()

    now := time.Now().UTC()
    _ = database.CreateUserSessionClient(nil, &models.UserSessionClient{UserSessionId: s1.Id, ClientId: testClient.Id, Started: now.Add(-time.Hour), LastAccessed: now.Add(-5 * time.Minute)})
    _ = database.CreateUserSessionClient(nil, &models.UserSessionClient{UserSessionId: s2.Id, ClientId: testClient.Id, Started: now.Add(-time.Hour), LastAccessed: now.Add(-5 * time.Minute)})

    url := config.GetAuthServer().BaseURL + "/api/v1/account/sessions"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var out api.GetUserSessionsResponse
    err = json.NewDecoder(resp.Body).Decode(&out)
    assert.NoError(t, err)
    assert.GreaterOrEqual(t, len(out.Sessions), 1)

    foundCurrent := false
    for _, s := range out.Sessions {
        assert.Greater(t, s.Id, int64(0))
        assert.NotEmpty(t, s.SessionIdentifier)
        assert.NotEmpty(t, s.StartedAt)
        assert.NotEmpty(t, s.DurationSinceStarted)
        assert.NotEmpty(t, s.LastAccessedAt)
        assert.NotEmpty(t, s.DurationSinceLastAccessed)
        assert.True(t, s.IsValid)
        // isCurrent must be present; true for the session associated to the access token (sid)
        if s.IsCurrent {
            foundCurrent = true
        }
    }
    assert.True(t, foundCurrent, "expected at least one session with isCurrent=true")
}

// Ensure invalid/expired sessions are filtered out
func TestAPIAccountSessionsGet_OnlyValidSessions(t *testing.T) {
    accessToken, user := getUserAccessTokenWithAccountScope(t)

    valid := &models.UserSession{
        SessionIdentifier:          uuid.New().String(),
        Started:                    time.Now().UTC().Add(-30 * time.Minute),
        LastAccessed:               time.Now().UTC().Add(-5 * time.Minute),
        AuthMethods:                "pwd",
        AcrLevel:                   "urn:goiabada:pwd",
        AuthTime:                   time.Now().UTC().Add(-30 * time.Minute),
        IpAddress:                  "192.168.1.100",
        DeviceName:                 "Valid Account Session",
        DeviceType:                 "computer",
        DeviceOS:                   "linux",
        Level2AuthConfigHasChanged: false,
        UserId:                     user.Id,
    }
    err := database.CreateUserSession(nil, valid)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUserSession(nil, valid.Id) }()

    expired := &models.UserSession{
        SessionIdentifier:          uuid.New().String(),
        Started:                    time.Now().UTC().Add(-25 * time.Hour),
        LastAccessed:               time.Now().UTC().Add(-24 * time.Hour),
        AuthMethods:                "pwd",
        AcrLevel:                   "urn:goiabada:pwd",
        AuthTime:                   time.Now().UTC().Add(-25 * time.Hour),
        IpAddress:                  "192.168.1.100",
        DeviceName:                 "Expired Account Session",
        DeviceType:                 "computer",
        DeviceOS:                   "linux",
        Level2AuthConfigHasChanged: false,
        UserId:                     user.Id,
    }
    err = database.CreateUserSession(nil, expired)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUserSession(nil, expired.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/account/sessions"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var out api.GetUserSessionsResponse
    err = json.NewDecoder(resp.Body).Decode(&out)
    assert.NoError(t, err)

    // Should not include the expired session identifier
    for _, s := range out.Sessions {
        assert.NotEqual(t, expired.SessionIdentifier, s.SessionIdentifier)
    }
}

// DELETE /api/v1/account/sessions/{id} — success and ownership enforced
func TestAPIAccountSessionDelete_Success(t *testing.T) {
    accessToken, user := getUserAccessTokenWithAccountScope(t)

    session := createTestUserSession(t, user.Id, uuid.New().String())

    url := config.GetAuthServer().BaseURL + "/api/v1/account/sessions/" + strconv.FormatInt(session.Id, 10)
    resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var out api.SuccessResponse
    err := json.NewDecoder(resp.Body).Decode(&out)
    assert.NoError(t, err)
    assert.True(t, out.Success)

    // ensure deleted
    s, err := database.GetUserSessionById(nil, session.Id)
    assert.NoError(t, err)
    assert.Nil(t, s)
}

func TestAPIAccountSessionDelete_ForbiddenOnOtherUsersSession(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope(t)

    // Create another user and a session for them
    other := &models.User{Subject: uuid.New(), Enabled: true, Email: "other-" + uuid.New().String()[:8] + "@acctsess.test"}
    err := database.CreateUser(nil, other)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUser(nil, other.Id) }()

    otherSession := createTestUserSession(t, other.Id, uuid.New().String())
    defer func() { _ = database.DeleteUserSession(nil, otherSession.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/account/sessions/" + strconv.FormatInt(otherSession.Id, 10)
    resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusForbidden, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Forbidden", errResp.Error.Message)
}

func TestAPIAccountSessions_UnauthorizedAndScope(t *testing.T) {
    url := config.GetAuthServer().BaseURL + "/api/v1/account/sessions"

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

    // Insufficient scope
    tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
    resp3 := makeAPIRequest(t, "GET", url, tok, nil)
    defer resp3.Body.Close()
    assert.Equal(t, http.StatusForbidden, resp3.StatusCode)
    body3, _ := io.ReadAll(resp3.Body)
    assert.Equal(t, "Insufficient scope", strings.TrimSpace(string(body3)))
}

func TestAPIAccountSessionDelete_UnauthorizedAndInvalidId(t *testing.T) {
    // No token
    url := config.GetAuthServer().BaseURL + "/api/v1/account/sessions/123"
    req, err := http.NewRequest("DELETE", url, nil)
    assert.NoError(t, err)
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

    // With token but invalid id formats
    accessToken, _ := getUserAccessTokenWithAccountScope(t)

    // non-numeric
    url2 := config.GetAuthServer().BaseURL + "/api/v1/account/sessions/abc"
    resp2 := makeAPIRequest(t, "DELETE", url2, accessToken, nil)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var errResp2 api.ErrorResponse
    _ = json.NewDecoder(resp2.Body).Decode(&errResp2)
    assert.Equal(t, "User session ID is required", errResp2.Error.Message)

    // negative
    url3 := config.GetAuthServer().BaseURL + "/api/v1/account/sessions/-1"
    resp3 := makeAPIRequest(t, "DELETE", url3, accessToken, nil)
    defer resp3.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
    var errResp3 api.ErrorResponse
    _ = json.NewDecoder(resp3.Body).Decode(&errResp3)
    assert.Equal(t, "User session ID is required", errResp3.Error.Message)
}

func TestAPIAccountSessionDelete_NotFound(t *testing.T) {
    accessToken, _ := getUserAccessTokenWithAccountScope(t)
    url := config.GetAuthServer().BaseURL + "/api/v1/account/sessions/99999999"
    resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusNotFound, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "User session not found", errResp.Error.Message)
}
