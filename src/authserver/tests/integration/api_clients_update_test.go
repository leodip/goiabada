package integrationtests

import (
    "encoding/json"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "testing"

    "github.com/brianvoe/gofakeit/v6"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/encryption"
    "github.com/leodip/goiabada/core/enums"
    "github.com/leodip/goiabada/core/models"
    "github.com/stretchr/testify/assert"
)

// helper to create a client directly in DB
func createTestClientUnique(t *testing.T, authCodeEnabled bool) *models.Client {
    t.Helper()
    ident := "test-client-" + strings.ToLower(gofakeit.LetterN(10))
    client := &models.Client{
        ClientIdentifier:         ident,
        Description:              "Test client",
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 true,
        AuthorizationCodeEnabled: authCodeEnabled,
        ClientCredentialsEnabled: false,
        DefaultAcrLevel:          enums.AcrLevel2Optional,
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    return client
}

// TestAPIClientUpdatePut_Success verifies a successful update including ACR change when auth code is enabled
func TestAPIClientUpdatePut_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create a client with authorization code enabled so defaultAcrLevel applies
    client := createTestClientUnique(t, true)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    updateReq := api.UpdateClientSettingsRequest{
        ClientIdentifier: client.ClientIdentifier + "-upd",
        Description:      "  Updated description  ",
        Enabled:          !client.Enabled,
        ConsentRequired:  !client.ConsentRequired,
        DefaultAcrLevel:  "urn:goiabada:level1",
    }

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
    resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var updateResp api.UpdateClientResponse
    err := json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)

    // Response reflects updates (description trimmed by sanitizer)
    assert.Equal(t, updateReq.ClientIdentifier, updateResp.Client.ClientIdentifier)
    assert.Equal(t, "Updated description", updateResp.Client.Description)
    assert.Equal(t, updateReq.Enabled, updateResp.Client.Enabled)
    assert.Equal(t, updateReq.ConsentRequired, updateResp.Client.ConsentRequired)
    assert.Equal(t, updateReq.DefaultAcrLevel, updateResp.Client.DefaultAcrLevel)

    // Verify DB persisted changes
    refreshed, err2 := database.GetClientById(nil, client.Id)
    assert.NoError(t, err2)
    assert.NotNil(t, refreshed)
    assert.Equal(t, updateReq.ClientIdentifier, refreshed.ClientIdentifier)
    assert.Equal(t, "Updated description", refreshed.Description)
    assert.Equal(t, updateReq.Enabled, refreshed.Enabled)
    assert.Equal(t, updateReq.ConsentRequired, refreshed.ConsentRequired)
    assert.Equal(t, enums.AcrLevel1, refreshed.DefaultAcrLevel)
}

func TestAPIClientUpdatePut_ValidationErrors(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := createTestClientUnique(t, true)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    cases := []struct {
        name           string
        req            api.UpdateClientSettingsRequest
        expectedStatus int
    }{
        {"empty identifier", api.UpdateClientSettingsRequest{ClientIdentifier: "", Description: "desc"}, http.StatusBadRequest},
        {"desc too long", api.UpdateClientSettingsRequest{ClientIdentifier: client.ClientIdentifier, Description: strings.Repeat("a", 101)}, http.StatusBadRequest},
        {"invalid identifier format", api.UpdateClientSettingsRequest{ClientIdentifier: "invalid id", Description: "x"}, http.StatusBadRequest},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
            resp := makeAPIRequest(t, "PUT", url, accessToken, tc.req)
            defer resp.Body.Close()
            assert.Equal(t, tc.expectedStatus, resp.StatusCode)
        })
    }
}

func TestAPIClientUpdatePut_DuplicateIdentifier(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    a := createTestClientUnique(t, true)
    defer func() { _ = database.DeleteClient(nil, a.Id) }()
    b := createTestClientUnique(t, true)
    defer func() { _ = database.DeleteClient(nil, b.Id) }()

    // Try to update B to use A's identifier
    updateReq := api.UpdateClientSettingsRequest{ClientIdentifier: a.ClientIdentifier, Description: "upd"}
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(b.Id, 10)
    resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIClientUpdatePut_SameIdentifierAllowed(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := createTestClientUnique(t, true)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    updateReq := api.UpdateClientSettingsRequest{
        ClientIdentifier: client.ClientIdentifier, // same identifier
        Description:      "Updated",
        Enabled:          client.Enabled,
        ConsentRequired:  client.ConsentRequired,
    }
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
    resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAPIClientUpdatePut_NotFoundAndInvalidId(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Not found
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/99999"
    resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientSettingsRequest{ClientIdentifier: "valid-ident", Description: "x"})
    defer resp.Body.Close()
    assert.Equal(t, http.StatusNotFound, resp.StatusCode)

    // Invalid id cases
    cases := []struct {
        name   string
        id     string
        status int
    }{
        {"non-numeric", "abc", http.StatusBadRequest},
        {"empty", "", http.StatusMethodNotAllowed}, // No PUT route matches /clients/
        {"negative", "-1", http.StatusNotFound},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + tc.id
            resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientSettingsRequest{ClientIdentifier: "valid-ident", Description: "x"})
            defer resp.Body.Close()
            assert.Equal(t, tc.status, resp.StatusCode)
        })
    }
}

func TestAPIClientUpdatePut_InvalidRequestBodyAndUnauthorized(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := createTestClientUnique(t, true)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Invalid body
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
    req, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

    // Unauthorized
    req2, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    resp2, err := httpClient.Do(req2)
    assert.NoError(t, err)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestAPIClientUpdatePut_ACRRuleEnforcement(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Client with auth code disabled
    client := createTestClientUnique(t, false)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Attempt to set DefaultAcrLevel when not applicable should be rejected
    updateReq := api.UpdateClientSettingsRequest{
        ClientIdentifier: client.ClientIdentifier,
        Description:      client.Description,
        Enabled:          client.Enabled,
        ConsentRequired:  client.ConsentRequired,
        DefaultAcrLevel:  "urn:goiabada:level2_mandatory",
    }
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
    resp := makeAPIRequest(t, "PUT", url, accessToken, updateReq)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAPIClientUpdatePut_WhitespaceHandling(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := createTestClientUnique(t, true)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // With whitespace around identifier should fail validation
    badReq := api.UpdateClientSettingsRequest{
        ClientIdentifier: "  " + client.ClientIdentifier + "  ",
        Description:      "  Spaced desc  ",
    }
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
    resp := makeAPIRequest(t, "PUT", url, accessToken, badReq)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

    // Trimmed identifier should succeed; description should be trimmed
    goodReq := api.UpdateClientSettingsRequest{
        ClientIdentifier: client.ClientIdentifier,
        Description:      "  Spaced desc  ",
    }
    resp2 := makeAPIRequest(t, "PUT", url, accessToken, goodReq)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusOK, resp2.StatusCode)
    var updateResp api.UpdateClientResponse
    err := json.NewDecoder(resp2.Body).Decode(&updateResp)
    assert.NoError(t, err)
    assert.Equal(t, "Spaced desc", updateResp.Client.Description)
}

func TestAPIClientUpdatePut_InsufficientScope(t *testing.T) {
    // Create a token with only auth-server:userinfo scope
    clientSecret := gofakeit.Password(true, true, true, true, false, 32)
    settings, err := database.GetSettingsById(nil, 1)
    assert.NoError(t, err)
    clientSecretEncrypted, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
    assert.NoError(t, err)

    client := &models.Client{
        ClientIdentifier:         "inscope-client-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        ClientCredentialsEnabled: true,
        IsPublic:                 false,
        ClientSecretEncrypted:    clientSecretEncrypted,
    }
    err = database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Grant auth-server:userinfo permission
    authRes, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
    assert.NoError(t, err)
    perms, err := database.GetPermissionsByResourceId(nil, authRes.Id)
    assert.NoError(t, err)
    var userinfoPerm *models.Permission
    for i := range perms {
        if perms[i].PermissionIdentifier == constants.UserinfoPermissionIdentifier {
            userinfoPerm = &perms[i]
            break
        }
    }
    assert.NotNil(t, userinfoPerm)
    err = database.CreateClientPermission(nil, &models.ClientPermission{ClientId: client.Id, PermissionId: userinfoPerm.Id})
    assert.NoError(t, err)

    // Get token with only auth-server:userinfo scope
    httpClient := createHttpClient(t)
    destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
    formData := url.Values{
        "grant_type":    {"client_credentials"},
        "client_id":     {client.ClientIdentifier},
        "client_secret": {clientSecret},
        "scope":         {constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier},
    }
    data := postToTokenEndpoint(t, httpClient, destUrl, formData)
    accessToken, ok := data["access_token"].(string)
    assert.True(t, ok)
    assert.NotEmpty(t, accessToken)

    // Create a target client to attempt updating
    target := createTestClientUnique(t, true)
    defer func() { _ = database.DeleteClient(nil, target.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10)
    reqBody := api.UpdateClientSettingsRequest{ClientIdentifier: target.ClientIdentifier, Description: "x"}
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
