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
    "github.com/leodip/goiabada/core/stringutil"
    "github.com/stretchr/testify/assert"
)

// PUT /api/v1/admin/clients/{id}/web-origins

func TestAPIClientWebOriginsPut_Success_AddRemoveAndNormalize(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create a confidential client with auth code enabled
    clientSecret := stringutil.GenerateSecurityRandomString(60)
    settings, err := database.GetSettingsById(nil, 1)
    assert.NoError(t, err)
    enc, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
    assert.NoError(t, err)
    client := &models.Client{
        ClientIdentifier:         "weborig-succ-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 false,
        ClientSecretEncrypted:    enc,
        AuthorizationCodeEnabled: true,
        ClientCredentialsEnabled: false,
    }
    err = database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Seed existing web origins
    originA := "https://a.example.com"
    originB := "https://b.example.com"
    err = database.CreateWebOrigin(nil, &models.WebOrigin{ClientId: client.Id, Origin: originA})
    assert.NoError(t, err)
    err = database.CreateWebOrigin(nil, &models.WebOrigin{ClientId: client.Id, Origin: originB})
    assert.NoError(t, err)

    // Desired: keep A (with spaces and uppercase to test trimming+lowercasing), remove B, add C
    originAMixed := "  HTTPS://A.EXAMPLE.COM  "
    originC := "https://c.example.com"
    reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{originAMixed, originC}}

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/web-origins"
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    var updateResp api.UpdateClientResponse
    err = json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)

    // Response should include exactly a.example.com and c.example.com in lowercase
    got := map[string]bool{}
    for _, wo := range updateResp.Client.WebOrigins {
        got[wo.Origin] = true
    }
    assert.Len(t, updateResp.Client.WebOrigins, 2)
    assert.True(t, got["https://a.example.com"])
    assert.True(t, got[originC])

    // Verify DB reflects the change
    refreshed, err := database.GetClientById(nil, client.Id)
    assert.NoError(t, err)
    err = database.ClientLoadWebOrigins(nil, refreshed)
    assert.NoError(t, err)
    gotDB := map[string]bool{}
    for _, wo := range refreshed.WebOrigins {
        gotDB[wo.Origin] = true
    }
    assert.Len(t, refreshed.WebOrigins, 2)
    assert.True(t, gotDB["https://a.example.com"])
    assert.True(t, gotDB[originC])
    assert.False(t, gotDB[originB])
}

func TestAPIClientWebOriginsPut_AuthCodeDisabledRejected(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := &models.Client{
        ClientIdentifier:         "weborig-disabled-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 true,
        AuthorizationCodeEnabled: false,
        ClientCredentialsEnabled: false,
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com"}}
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/web-origins"
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

    var body map[string]interface{}
    _ = json.NewDecoder(resp.Body).Decode(&body)
    if body["error"] != nil {
        msg := body["error"].(map[string]interface{})["message"].(string)
        assert.Equal(t, "Authorization code flow is disabled for this client.", msg)
    }
}

func TestAPIClientWebOriginsPut_SystemLevelClientRejected(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Find system-level admin console client id
    listURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
    resp := makeAPIRequest(t, "GET", listURL, accessToken, nil)
    defer func() { _ = resp.Body.Close() }()
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

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysId, 10) + "/web-origins"
    reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com"}}
    resp2 := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var body map[string]interface{}
    _ = json.NewDecoder(resp2.Body).Decode(&body)
    if body["error"] != nil {
        msg := body["error"].(map[string]interface{})["message"].(string)
        assert.Equal(t, "Trying to edit a system level client", msg)
    }
}

func TestAPIClientWebOriginsPut_DuplicateInvalidWrongSchemeAndEmpty(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Auth code enabled client
    client := &models.Client{
        ClientIdentifier:         "weborig-vali-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 true,
        AuthorizationCodeEnabled: true,
        ClientCredentialsEnabled: false,
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    baseURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/web-origins"

    // Duplicate (case-insensitive)
    reqDup := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://dup.example", "HTTPS://DUP.EXAMPLE"}}
    resp := makeAPIRequest(t, "PUT", baseURL, accessToken, reqDup)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var bodyDup map[string]interface{}
    _ = json.NewDecoder(resp.Body).Decode(&bodyDup)
    if bodyDup["error"] != nil {
        msg := bodyDup["error"].(map[string]interface{})["message"].(string)
        assert.Equal(t, "Duplicate web origins are not allowed", msg)
    }

    // Invalid URL
    reqInv := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"not-a-url"}}
    resp2 := makeAPIRequest(t, "PUT", baseURL, accessToken, reqInv)
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var bodyInv map[string]interface{}
    _ = json.NewDecoder(resp2.Body).Decode(&bodyInv)
    if bodyInv["error"] != nil {
        msg := bodyInv["error"].(map[string]interface{})["message"].(string)
        assert.Equal(t, "Invalid web origin: not-a-url", msg)
    }

    // Wrong scheme
    reqScheme := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"ftp://example.com"}}
    resp3 := makeAPIRequest(t, "PUT", baseURL, accessToken, reqScheme)
    defer func() { _ = resp3.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
    var bodyScheme map[string]interface{}
    _ = json.NewDecoder(resp3.Body).Decode(&bodyScheme)
    if bodyScheme["error"] != nil {
        msg := bodyScheme["error"].(map[string]interface{})["message"].(string)
        assert.Equal(t, "Web origin must use http or https scheme", msg)
    }

    // Empty (or whitespace only)
    reqEmpty := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"  "}}
    resp4 := makeAPIRequest(t, "PUT", baseURL, accessToken, reqEmpty)
    defer func() { _ = resp4.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp4.StatusCode)
    var bodyEmpty map[string]interface{}
    _ = json.NewDecoder(resp4.Body).Decode(&bodyEmpty)
    if bodyEmpty["error"] != nil {
        msg := bodyEmpty["error"].(map[string]interface{})["message"].(string)
        assert.Equal(t, "Web origin cannot be empty", msg)
    }
}

func TestAPIClientWebOriginsPut_NotFound_InvalidId_InvalidBody_Unauthorized(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Not found
    urlNF := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/999999/web-origins"
    resp := makeAPIRequest(t, "PUT", urlNF, accessToken, api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com"}})
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusNotFound, resp.StatusCode)
    var nf map[string]interface{}
    _ = json.NewDecoder(resp.Body).Decode(&nf)
    if nf["error"] != nil {
        msg := nf["error"].(map[string]interface{})["message"].(string)
        assert.Equal(t, "Client not found", msg)
    }

    // Invalid id (non-numeric)
    urlBad := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/abc/web-origins"
    resp2 := makeAPIRequest(t, "PUT", urlBad, accessToken, api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com"}})
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var bad map[string]interface{}
    _ = json.NewDecoder(resp2.Body).Decode(&bad)
    if bad["error"] != nil {
        msg := bad["error"].(map[string]interface{})["message"].(string)
        assert.Equal(t, "Invalid client ID", msg)
    }

    // Invalid body
    client2 := &models.Client{
        ClientIdentifier:         "weborig-bad-body-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 true,
        AuthorizationCodeEnabled: true,
        ClientCredentialsEnabled: false,
    }
    err := database.CreateClient(nil, client2)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client2.Id) }()

    urlIB := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client2.Id, 10) + "/web-origins"
    req, err := http.NewRequest("PUT", urlIB, nil)
    assert.NoError(t, err)
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")
    httpClient := createHttpClient(t)
    resp3, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer func() { _ = resp3.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
    var ib map[string]interface{}
    _ = json.NewDecoder(resp3.Body).Decode(&ib)
    if ib["error"] != nil {
        msg := ib["error"].(map[string]interface{})["message"].(string)
        assert.Equal(t, "Invalid request body", msg)
    }

    // Unauthorized
    req2, err := http.NewRequest("PUT", urlIB, nil)
    assert.NoError(t, err)
    resp4, err := httpClient.Do(req2)
    assert.NoError(t, err)
    defer func() { _ = resp4.Body.Close() }()
    assert.Equal(t, http.StatusUnauthorized, resp4.StatusCode)
}

func TestAPIClientWebOriginsPut_InsufficientScope(t *testing.T) {
    // Create a client with only authserver:userinfo scope
    clientSecret := stringutil.GenerateSecurityRandomString(60)
    settings, err := database.GetSettingsById(nil, 1)
    assert.NoError(t, err)
    enc, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
    assert.NoError(t, err)

    client := &models.Client{
        ClientIdentifier:         "weborig-inscope-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        ClientCredentialsEnabled: true,
        IsPublic:                 false,
        ClientSecretEncrypted:    enc,
    }
    err = database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Grant auth-server:userinfo permission only
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

    // Get token with only authserver:userinfo scope
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

    // Create a target client with auth code enabled
    target := &models.Client{
        ClientIdentifier:         "weborig-target-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        IsPublic:                 true,
        AuthorizationCodeEnabled: true,
        ClientCredentialsEnabled: false,
    }
    err = database.CreateClient(nil, target)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, target.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/web-origins"
    reqBody := api.UpdateClientWebOriginsRequest{WebOrigins: []string{"https://example.com"}}
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

