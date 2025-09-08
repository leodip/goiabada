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
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/encryption"
    "github.com/leodip/goiabada/core/models"
    "github.com/stretchr/testify/assert"
)

// TestAPIClientTokensPut_Success verifies token settings update works and persists
func TestAPIClientTokensPut_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := createTestClientUnique(t, true)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    req := api.UpdateClientTokensRequest{
        TokenExpirationInSeconds:                3600,
        RefreshTokenOfflineIdleTimeoutInSeconds: 1000,
        RefreshTokenOfflineMaxLifetimeInSeconds: 2000,
        IncludeOpenIDConnectClaimsInAccessToken: "on",
    }

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/tokens"
    resp := makeAPIRequest(t, "PUT", url, accessToken, req)
    defer resp.Body.Close()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var updateResp api.UpdateClientResponse
    err := json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)

    assert.Equal(t, req.TokenExpirationInSeconds, updateResp.Client.TokenExpirationInSeconds)
    assert.Equal(t, req.RefreshTokenOfflineIdleTimeoutInSeconds, updateResp.Client.RefreshTokenOfflineIdleTimeoutInSeconds)
    assert.Equal(t, req.RefreshTokenOfflineMaxLifetimeInSeconds, updateResp.Client.RefreshTokenOfflineMaxLifetimeInSeconds)
    assert.Equal(t, req.IncludeOpenIDConnectClaimsInAccessToken, updateResp.Client.IncludeOpenIDConnectClaimsInAccessToken)

    refreshed, err2 := database.GetClientById(nil, client.Id)
    assert.NoError(t, err2)
    assert.NotNil(t, refreshed)
    assert.Equal(t, req.TokenExpirationInSeconds, refreshed.TokenExpirationInSeconds)
    assert.Equal(t, req.RefreshTokenOfflineIdleTimeoutInSeconds, refreshed.RefreshTokenOfflineIdleTimeoutInSeconds)
    assert.Equal(t, req.RefreshTokenOfflineMaxLifetimeInSeconds, refreshed.RefreshTokenOfflineMaxLifetimeInSeconds)
    assert.Equal(t, req.IncludeOpenIDConnectClaimsInAccessToken, refreshed.IncludeOpenIDConnectClaimsInAccessToken)
}

func TestAPIClientTokensPut_ValidationErrors(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := createTestClientUnique(t, true)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    baseURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/tokens"

    // Too large values
    tooLarge := 160000001
    cases := []struct{
        name string
        req  api.UpdateClientTokensRequest
        want string
    }{
        {"token_exp_too_large", api.UpdateClientTokensRequest{TokenExpirationInSeconds: tooLarge, RefreshTokenOfflineIdleTimeoutInSeconds: 1, RefreshTokenOfflineMaxLifetimeInSeconds: 2, IncludeOpenIDConnectClaimsInAccessToken: "default"}, "Token expiration in seconds must be between 0 and"},
        {"idle_too_large", api.UpdateClientTokensRequest{TokenExpirationInSeconds: 1, RefreshTokenOfflineIdleTimeoutInSeconds: tooLarge, RefreshTokenOfflineMaxLifetimeInSeconds: tooLarge, IncludeOpenIDConnectClaimsInAccessToken: "default"}, "idle timeout in seconds must be between 0 and"},
        {"maxlife_too_large", api.UpdateClientTokensRequest{TokenExpirationInSeconds: 1, RefreshTokenOfflineIdleTimeoutInSeconds: 1, RefreshTokenOfflineMaxLifetimeInSeconds: tooLarge, IncludeOpenIDConnectClaimsInAccessToken: "default"}, "max lifetime in seconds must be between 0 and"},
        {"idle_gt_maxlife", api.UpdateClientTokensRequest{TokenExpirationInSeconds: 1, RefreshTokenOfflineIdleTimeoutInSeconds: 5, RefreshTokenOfflineMaxLifetimeInSeconds: 4, IncludeOpenIDConnectClaimsInAccessToken: "default"}, "idle timeout cannot be greater than max lifetime"},
        {"invalid_three_state", api.UpdateClientTokensRequest{TokenExpirationInSeconds: 1, RefreshTokenOfflineIdleTimeoutInSeconds: 1, RefreshTokenOfflineMaxLifetimeInSeconds: 2, IncludeOpenIDConnectClaimsInAccessToken: "invalid"}, "Invalid value for includeOpenIDConnectClaimsInAccessToken"},
        {"negatives_rejected", api.UpdateClientTokensRequest{TokenExpirationInSeconds: -1, RefreshTokenOfflineIdleTimeoutInSeconds: -1, RefreshTokenOfflineMaxLifetimeInSeconds: -1, IncludeOpenIDConnectClaimsInAccessToken: "default"}, "must be between 0 and"},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            resp := makeAPIRequest(t, "PUT", baseURL, accessToken, tc.req)
            defer resp.Body.Close()
            assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
            var body map[string]interface{}
            _ = json.NewDecoder(resp.Body).Decode(&body)
            if body["error"] != nil {
                msg := body["error"].(map[string]interface{})["message"].(string)
                assert.Contains(t, strings.ToLower(msg), strings.ToLower(tc.want))
            } else {
                t.Fatalf("expected JSON error body")
            }
        })
    }
}

func TestAPIClientTokensPut_NotFoundAndInvalidId(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Not found
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/999999/tokens"
    resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientTokensRequest{TokenExpirationInSeconds: 1, RefreshTokenOfflineIdleTimeoutInSeconds: 1, RefreshTokenOfflineMaxLifetimeInSeconds: 2, IncludeOpenIDConnectClaimsInAccessToken: "default"})
    defer resp.Body.Close()
    assert.Equal(t, http.StatusNotFound, resp.StatusCode)
    var body map[string]interface{}
    _ = json.NewDecoder(resp.Body).Decode(&body)
    if body["error"] != nil {
        msg := body["error"].(map[string]interface{})["message"].(string)
        assert.Contains(t, msg, "Client not found")
    }

    // Invalid id format
    badURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/abc/tokens"
    resp2 := makeAPIRequest(t, "PUT", badURL, accessToken, api.UpdateClientTokensRequest{TokenExpirationInSeconds: 1, RefreshTokenOfflineIdleTimeoutInSeconds: 1, RefreshTokenOfflineMaxLifetimeInSeconds: 2, IncludeOpenIDConnectClaimsInAccessToken: "default"})
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var body2 map[string]interface{}
    _ = json.NewDecoder(resp2.Body).Decode(&body2)
    if body2["error"] != nil {
        msg := body2["error"].(map[string]interface{})["message"].(string)
        assert.Contains(t, msg, "Invalid client ID")
    }
}

func TestAPIClientTokensPut_SystemLevelClientRejected(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Find admin-console-client id via list
    listURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
    resp := makeAPIRequest(t, "GET", listURL, accessToken, nil)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusOK, resp.StatusCode)
    var listResp api.GetClientsResponse
    err := json.NewDecoder(resp.Body).Decode(&listResp)
    assert.NoError(t, err)

    var sysId int64
    for _, c := range listResp.Clients {
        if c.ClientIdentifier == constants.AdminConsoleClientIdentifier {
            sysId = c.Id
            break
        }
    }
    if sysId == 0 {
        t.Skip("system-level client not found")
    }

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysId, 10) + "/tokens"
    resp2 := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientTokensRequest{TokenExpirationInSeconds: 1, RefreshTokenOfflineIdleTimeoutInSeconds: 1, RefreshTokenOfflineMaxLifetimeInSeconds: 2, IncludeOpenIDConnectClaimsInAccessToken: "default"})
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var body map[string]interface{}
    _ = json.NewDecoder(resp2.Body).Decode(&body)
    if body["error"] != nil {
        msg := body["error"].(map[string]interface{})["message"].(string)
        assert.Contains(t, strings.ToLower(msg), "system level client")
    }
}

func TestAPIClientTokensPut_InvalidRequestBodyAndUnauthorized(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := createTestClientUnique(t, true)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/tokens"

    // Invalid body (nil/empty)
    req, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var body map[string]interface{}
    _ = json.NewDecoder(resp.Body).Decode(&body)
    if body["error"] != nil {
        msg := body["error"].(map[string]interface{})["message"].(string)
        assert.Contains(t, msg, "Invalid request body")
    }

    // Unauthorized (no Authorization header)
    req2, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    resp2, err := httpClient.Do(req2)
    assert.NoError(t, err)
    defer resp2.Body.Close()
    assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestAPIClientTokensPut_InsufficientScope(t *testing.T) {
    // Create a client with only auth-server:userinfo scope
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

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/tokens"
    reqBody := api.UpdateClientTokensRequest{TokenExpirationInSeconds: 1, RefreshTokenOfflineIdleTimeoutInSeconds: 1, RefreshTokenOfflineMaxLifetimeInSeconds: 2, IncludeOpenIDConnectClaimsInAccessToken: "default"}
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer resp.Body.Close()
    assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

