package integrationtests

import (
    "encoding/json"
    "net/http"
    "strconv"
    "testing"
    "time"

    "github.com/google/uuid"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/models"
    "github.com/stretchr/testify/assert"
)

// TestAPIClientSessionsGet_Success tests GET /api/v1/admin/clients/{id}/sessions happy path
func TestAPIClientSessionsGet_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create a client
    testClient := &models.Client{
        ClientIdentifier:         "test-client-sessions-" + uuid.New().String()[:8],
        ClientSecretEncrypted:    []byte("encrypted-secret"),
        Description:              "Test Client for Sessions",
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 false,
        AuthorizationCodeEnabled: true,
        ClientCredentialsEnabled: false,
    }
    err := database.CreateClient(nil, testClient)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

    // Create a user
    testUser := &models.User{
        Subject:       uuid.New(),
        Enabled:       true,
        Email:         "testuser@client-sessions-success.test",
        GivenName:     "Test",
        FamilyName:    "User",
        EmailVerified: true,
    }
    err = database.CreateUser(nil, testUser)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUser(nil, testUser.Id) }()

    // Create sessions
    s1 := createTestUserSession(t, testUser.Id, uuid.New().String())
    s2 := createTestUserSession(t, testUser.Id, uuid.New().String())
    defer func() {
        _ = database.DeleteUserSession(nil, s1.Id)
        _ = database.DeleteUserSession(nil, s2.Id)
    }()

    // Link sessions to client
    now := time.Now().UTC()
    usc1 := &models.UserSessionClient{UserSessionId: s1.Id, ClientId: testClient.Id, Started: now.Add(-time.Hour), LastAccessed: now.Add(-time.Minute * 5)}
    err = database.CreateUserSessionClient(nil, usc1)
    assert.NoError(t, err)
    usc2 := &models.UserSessionClient{UserSessionId: s2.Id, ClientId: testClient.Id, Started: now.Add(-time.Hour), LastAccessed: now.Add(-time.Minute * 5)}
    err = database.CreateUserSessionClient(nil, usc2)
    assert.NoError(t, err)

    // Call endpoint
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var out api.GetUserSessionsResponse
    err = json.NewDecoder(resp.Body).Decode(&out)
    assert.NoError(t, err)
    assert.Len(t, out.Sessions, 2)

    for _, s := range out.Sessions {
        assert.Greater(t, s.Id, int64(0))
        assert.NotEmpty(t, s.SessionIdentifier)
        assert.NotEmpty(t, s.StartedAt)
        assert.NotEmpty(t, s.DurationSinceStarted)
        assert.NotEmpty(t, s.LastAccessedAt)
        assert.NotEmpty(t, s.DurationSinceLastAccessed)
        assert.Equal(t, "192.168.1.100", s.IpAddress)
        assert.Equal(t, "Test Device", s.DeviceName)
        assert.Equal(t, "computer", s.DeviceType)
        assert.Equal(t, "linux", s.DeviceOS)
        assert.True(t, s.IsValid)
        assert.Equal(t, testUser.Id, s.UserId)
        assert.Contains(t, s.ClientIdentifiers, testClient.ClientIdentifier)
    }
}

func TestAPIClientSessionsGet_EmptySessions(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create a client without linked sessions
    testClient := &models.Client{
        ClientIdentifier:         "test-client-empty-" + uuid.New().String()[:8],
        ClientSecretEncrypted:    []byte("encrypted-secret"),
        Description:              "Empty Client",
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 false,
        AuthorizationCodeEnabled: true,
        ClientCredentialsEnabled: false,
    }
    err := database.CreateClient(nil, testClient)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var out api.GetUserSessionsResponse
    err = json.NewDecoder(resp.Body).Decode(&out)
    assert.NoError(t, err)
    assert.Len(t, out.Sessions, 0)
}

func TestAPIClientSessionsGet_ClientNotFound(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/999999/sessions"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusNotFound, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Client not found", errResp.Error.Message)
}

func TestAPIClientSessionsGet_InvalidId(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    cases := []struct{
        name string
        clientId string
        expected int
    }{
        {"non-numeric", "abc", http.StatusBadRequest},
        {"negative", "-1", http.StatusNotFound},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + tc.clientId + "/sessions"
            resp := makeAPIRequest(t, "GET", url, accessToken, nil)
            defer resp.Body.Close()
            assert.Equal(t, tc.expected, resp.StatusCode)
            var errResp api.ErrorResponse
            _ = json.NewDecoder(resp.Body).Decode(&errResp)
            if tc.clientId == "abc" {
                assert.Equal(t, "Invalid client ID format", errResp.Error.Message)
            }
            if tc.clientId == "-1" {
                assert.Equal(t, "Client not found", errResp.Error.Message)
            }
        })
    }
}

func TestAPIClientSessionsGet_Unauthorized(t *testing.T) {
    // Create a client
    testClient := &models.Client{
        ClientIdentifier:         "test-client-unauth-" + uuid.New().String()[:8],
        ClientSecretEncrypted:    []byte("encrypted-secret"),
        Description:              "Client",
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 false,
        AuthorizationCodeEnabled: true,
        ClientCredentialsEnabled: false,
    }
    err := database.CreateClient(nil, testClient)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"
    req, err := http.NewRequest("GET", url, nil)
    assert.NoError(t, err)
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAPIClientSessionsGet_OnlyValidSessions(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Client
    testClient := &models.Client{
        ClientIdentifier:         "test-client-valid-" + uuid.New().String()[:8],
        ClientSecretEncrypted:    []byte("encrypted-secret"),
        Description:              "Client",
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 false,
        AuthorizationCodeEnabled: true,
        ClientCredentialsEnabled: false,
    }
    err := database.CreateClient(nil, testClient)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

    // User
    testUser := &models.User{
        Subject:       uuid.New(),
        Enabled:       true,
        Email:         "testuser@client-valid-sessions.test",
        GivenName:     "Test",
        FamilyName:    "User",
        EmailVerified: true,
    }
    err = database.CreateUser(nil, testUser)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUser(nil, testUser.Id) }()

    // Valid session
    valid := &models.UserSession{
        SessionIdentifier:          uuid.New().String(),
        Started:                    time.Now().UTC().Add(-30 * time.Minute),
        LastAccessed:               time.Now().UTC().Add(-5 * time.Minute),
        AuthMethods:                "pwd",
        AcrLevel:                   "urn:goiabada:pwd",
        AuthTime:                   time.Now().UTC().Add(-30 * time.Minute),
        IpAddress:                  "192.168.1.100",
        DeviceName:                 "Valid Session Device",
        DeviceType:                 "computer",
        DeviceOS:                   "linux",
        Level2AuthConfigHasChanged: false,
        UserId:                     testUser.Id,
    }
    err = database.CreateUserSession(nil, valid)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUserSession(nil, valid.Id) }()

    // Expired session
    expired := &models.UserSession{
        SessionIdentifier:          uuid.New().String(),
        Started:                    time.Now().UTC().Add(-25 * time.Hour),
        LastAccessed:               time.Now().UTC().Add(-24 * time.Hour),
        AuthMethods:                "pwd",
        AcrLevel:                   "urn:goiabada:pwd",
        AuthTime:                   time.Now().UTC().Add(-25 * time.Hour),
        IpAddress:                  "192.168.1.100",
        DeviceName:                 "Expired Session Device",
        DeviceType:                 "computer",
        DeviceOS:                   "linux",
        Level2AuthConfigHasChanged: false,
        UserId:                     testUser.Id,
    }
    err = database.CreateUserSession(nil, expired)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUserSession(nil, expired.Id) }()

    // Link both to client
    now := time.Now().UTC()
    err = database.CreateUserSessionClient(nil, &models.UserSessionClient{UserSessionId: valid.Id, ClientId: testClient.Id, Started: now.Add(-time.Hour), LastAccessed: now.Add(-5 * time.Minute)})
    assert.NoError(t, err)
    err = database.CreateUserSessionClient(nil, &models.UserSessionClient{UserSessionId: expired.Id, ClientId: testClient.Id, Started: now.Add(-26 * time.Hour), LastAccessed: now.Add(-25 * time.Hour)})
    assert.NoError(t, err)

    // Call endpoint
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var out api.GetUserSessionsResponse
    err = json.NewDecoder(resp.Body).Decode(&out)
    assert.NoError(t, err)
    assert.Len(t, out.Sessions, 1)
    assert.Equal(t, valid.SessionIdentifier, out.Sessions[0].SessionIdentifier)
    assert.Equal(t, "Valid Session Device", out.Sessions[0].DeviceName)
}

// Test default pagination (size=50) and size cap (max 100)
func TestAPIClientSessionsGet_PaginationDefaultAndCap(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Client
    testClient := &models.Client{
        ClientIdentifier:         "test-client-page-" + uuid.New().String()[:8],
        ClientSecretEncrypted:    []byte("encrypted-secret"),
        Description:              "Client",
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 false,
        AuthorizationCodeEnabled: true,
        ClientCredentialsEnabled: false,
    }
    err := database.CreateClient(nil, testClient)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, testClient.Id) }()

    // User
    testUser := &models.User{
        Subject:       uuid.New(),
        Enabled:       true,
        Email:         "testuser@client-page.test",
        GivenName:     "Test",
        FamilyName:    "User",
        EmailVerified: true,
    }
    err = database.CreateUser(nil, testUser)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteUser(nil, testUser.Id) }()

    // Create many valid sessions (e.g., 120)
    total := 120
    sessions := make([]*models.UserSession, 0, total)
    now := time.Now().UTC()
    for i := 0; i < total; i++ {
        s := &models.UserSession{
            SessionIdentifier:          uuid.New().String(),
            Started:                    now.Add(-time.Hour),
            LastAccessed:               now.Add(-time.Minute * 5),
            AuthMethods:                "pwd",
            AcrLevel:                   "urn:goiabada:pwd",
            AuthTime:                   now.Add(-time.Hour),
            IpAddress:                  "192.168.1.100",
            DeviceName:                 "Test Device",
            DeviceType:                 "computer",
            DeviceOS:                   "linux",
            Level2AuthConfigHasChanged: false,
            UserId:                     testUser.Id,
        }
        err := database.CreateUserSession(nil, s)
        assert.NoError(t, err)
        sessions = append(sessions, s)
        // Link to client
        usc := &models.UserSessionClient{UserSessionId: s.Id, ClientId: testClient.Id, Started: now.Add(-time.Hour), LastAccessed: now.Add(-time.Minute * 5)}
        err = database.CreateUserSessionClient(nil, usc)
        assert.NoError(t, err)
    }
    defer func() {
        for _, s := range sessions {
            _ = database.DeleteUserSession(nil, s.Id)
        }
    }()

    // Default pagination (no page/size): expect 50 items returned
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)
    var out api.GetUserSessionsResponse
    err = json.NewDecoder(resp.Body).Decode(&out)
    assert.NoError(t, err)
    assert.Len(t, out.Sessions, 50)

    // Request size over cap (e.g., 200) should cap at 100
    url2 := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(testClient.Id, 10) + "/sessions?size=200"
    resp2 := makeAPIRequest(t, "GET", url2, accessToken, nil)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusOK, resp2.StatusCode)
    var out2 api.GetUserSessionsResponse
    err = json.NewDecoder(resp2.Body).Decode(&out2)
    assert.NoError(t, err)
    assert.Len(t, out2.Sessions, 100)
}
