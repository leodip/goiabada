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

// PUT /api/v1/admin/clients/{id}/oauth2-flows

func TestAPIClientOAuth2FlowsPut_Success_PublicClient_ForcesNoClientCredentials(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create a public client
    client := &models.Client{
        ClientIdentifier:         "flows-public-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 true,
        AuthorizationCodeEnabled: false,
        ClientCredentialsEnabled: false,
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Try to enable both flows; client is public so client credentials must be forced to false
    reqBody := api.UpdateClientOAuth2FlowsRequest{AuthorizationCodeEnabled: true, ClientCredentialsEnabled: true}
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/oauth2-flows"
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusOK, resp.StatusCode)
    assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

    // Response reflects forced disabling of client credentials
    var updateResp api.UpdateClientResponse
    err = json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)
    assert.True(t, updateResp.Client.AuthorizationCodeEnabled)
    assert.False(t, updateResp.Client.ClientCredentialsEnabled)

    // Verify DB persisted: auth code enabled, client credentials forced false
    refreshed, err := database.GetClientById(nil, client.Id)
    assert.NoError(t, err)
    assert.True(t, refreshed.AuthorizationCodeEnabled)
    assert.True(t, refreshed.IsPublic)
    assert.False(t, refreshed.ClientCredentialsEnabled)
}

func TestAPIClientOAuth2FlowsPut_Success_ConfidentialClient_ToggleBoth(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create confidential client with a valid secret
    clientSecret := stringutil.GenerateSecurityRandomString(60)
    settings, err := database.GetSettingsById(nil, 1)
    assert.NoError(t, err)
    enc, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
    assert.NoError(t, err)
    client := &models.Client{
        ClientIdentifier:         "flows-conf-" + strings.ToLower(gofakeit.LetterN(8)),
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

    // Disable auth code, enable client credentials
    reqBody := api.UpdateClientOAuth2FlowsRequest{AuthorizationCodeEnabled: false, ClientCredentialsEnabled: true}
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/oauth2-flows"
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusOK, resp.StatusCode)

    // Response reflects toggles
    var updateResp api.UpdateClientResponse
    err = json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)
    assert.False(t, updateResp.Client.AuthorizationCodeEnabled)
    assert.True(t, updateResp.Client.ClientCredentialsEnabled)

    refreshed, err := database.GetClientById(nil, client.Id)
    assert.NoError(t, err)
    assert.False(t, refreshed.AuthorizationCodeEnabled)
    assert.True(t, refreshed.ClientCredentialsEnabled)
    assert.False(t, refreshed.IsPublic)
}

func TestAPIClientOAuth2FlowsPut_SystemLevelClientRejected(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Discover system-level admin console client Id
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

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysId, 10) + "/oauth2-flows"
    reqBody := api.UpdateClientOAuth2FlowsRequest{AuthorizationCodeEnabled: true, ClientCredentialsEnabled: false}
    resp2 := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var body map[string]interface{}
    _ = json.NewDecoder(resp2.Body).Decode(&body)
    if body["error"] != nil {
        msg := body["error"].(map[string]interface{})["message"].(string)
        assert.Contains(t, msg, "system level client")
    }
}

func TestAPIClientOAuth2FlowsPut_NotFoundAndInvalidId(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Not found
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/999999/oauth2-flows"
    resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientOAuth2FlowsRequest{AuthorizationCodeEnabled: true})
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusNotFound, resp.StatusCode)
    var nf map[string]interface{}
    _ = json.NewDecoder(resp.Body).Decode(&nf)
    if nf["error"] != nil {
        msg := nf["error"].(map[string]interface{})["message"].(string)
        assert.Contains(t, msg, "Client not found")
    }

    // Invalid id (non-numeric)
    url2 := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/abc/oauth2-flows"
    resp2 := makeAPIRequest(t, "PUT", url2, accessToken, api.UpdateClientOAuth2FlowsRequest{AuthorizationCodeEnabled: true})
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
    var body map[string]interface{}
    _ = json.NewDecoder(resp2.Body).Decode(&body)
    if body["error"] != nil {
        msg := body["error"].(map[string]interface{})["message"].(string)
        assert.Contains(t, msg, "Invalid client ID")
    }
}

func TestAPIClientOAuth2FlowsPut_InvalidRequestBodyAndUnauthorized(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := &models.Client{
        ClientIdentifier:         "flows-invalid-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 true,
        AuthorizationCodeEnabled: false,
        ClientCredentialsEnabled: false,
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/oauth2-flows"

    // Invalid body
    req, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Content-Type", "application/json")
    httpClient := createHttpClient(t)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var body map[string]interface{}
    _ = json.NewDecoder(resp.Body).Decode(&body)
    if body["error"] != nil {
        msg := body["error"].(map[string]interface{})["message"].(string)
        assert.Contains(t, msg, "Invalid request body")
    }

    // Unauthorized
    req2, err := http.NewRequest("PUT", url, nil)
    assert.NoError(t, err)
    resp2, err := httpClient.Do(req2)
    assert.NoError(t, err)
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestAPIClientOAuth2FlowsPut_InsufficientScope(t *testing.T) {
    // Token with only authserver:userinfo
    clientSecret := stringutil.GenerateSecurityRandomString(60)
    settings, err := database.GetSettingsById(nil, 1)
    assert.NoError(t, err)
    enc, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
    assert.NoError(t, err)

    client := &models.Client{
        ClientIdentifier:         "flows-inscope-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        ClientCredentialsEnabled: true,
        IsPublic:                 false,
        ClientSecretEncrypted:    enc,
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

    // Create a target client to attempt updating
    target := &models.Client{
        ClientIdentifier:         "flows-target-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        IsPublic:                 true,
        AuthorizationCodeEnabled: false,
        ClientCredentialsEnabled: false,
    }
    err = database.CreateClient(nil, target)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, target.Id) }()

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/oauth2-flows"
    reqBody := api.UpdateClientOAuth2FlowsRequest{AuthorizationCodeEnabled: true}
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestAPIClientOAuth2FlowsPut_BothDisabledAllowed(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Confidential client (has secret), start with auth code enabled
    clientSecret := stringutil.GenerateSecurityRandomString(60)
    settings, err := database.GetSettingsById(nil, 1)
    assert.NoError(t, err)
    enc, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
    assert.NoError(t, err)
    client := &models.Client{
        ClientIdentifier:         "flows-bothoff-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        ConsentRequired:          false,
        IsPublic:                 false,
        ClientSecretEncrypted:    enc,
        AuthorizationCodeEnabled: true,
        ClientCredentialsEnabled: true,
    }
    err = database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Disable both flows
    reqBody := api.UpdateClientOAuth2FlowsRequest{AuthorizationCodeEnabled: false, ClientCredentialsEnabled: false}
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/oauth2-flows"
    resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    // Response should reflect both disabled
    var updateResp api.UpdateClientResponse
    err = json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)
    assert.False(t, updateResp.Client.AuthorizationCodeEnabled)
    assert.False(t, updateResp.Client.ClientCredentialsEnabled)

    // DB should reflect both disabled
    refreshed, err := database.GetClientById(nil, client.Id)
    assert.NoError(t, err)
    assert.False(t, refreshed.AuthorizationCodeEnabled)
    assert.False(t, refreshed.ClientCredentialsEnabled)
}

// Implicit flow API tests

func TestAPIClientOAuth2FlowsPut_ImplicitGrantEnabled_UseGlobalSetting(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := &models.Client{
        ClientIdentifier:         "flows-implicit-global-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        IsPublic:                 true,
        AuthorizationCodeEnabled: true,
        ImplicitGrantEnabled:     nil, // Initially use global
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Update with nil (use global setting)
    reqBody := api.UpdateClientOAuth2FlowsRequest{
        AuthorizationCodeEnabled: true,
        ImplicitGrantEnabled:     nil, // Use global
    }
    apiURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/oauth2-flows"
    resp := makeAPIRequest(t, "PUT", apiURL, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var updateResp api.UpdateClientResponse
    err = json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)

    // DB should have nil (use global)
    refreshed, err := database.GetClientById(nil, client.Id)
    assert.NoError(t, err)
    assert.Nil(t, refreshed.ImplicitGrantEnabled, "ImplicitGrantEnabled should be nil (use global)")
}

func TestAPIClientOAuth2FlowsPut_ImplicitGrantEnabled_ExplicitEnable(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := &models.Client{
        ClientIdentifier:         "flows-implicit-on-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        IsPublic:                 true,
        AuthorizationCodeEnabled: true,
        ImplicitGrantEnabled:     nil,
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Explicitly enable implicit flow
    implicitEnabled := true
    reqBody := api.UpdateClientOAuth2FlowsRequest{
        AuthorizationCodeEnabled: true,
        ImplicitGrantEnabled:     &implicitEnabled,
    }
    apiURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/oauth2-flows"
    resp := makeAPIRequest(t, "PUT", apiURL, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var updateResp api.UpdateClientResponse
    err = json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)

    // DB should have true
    refreshed, err := database.GetClientById(nil, client.Id)
    assert.NoError(t, err)
    assert.NotNil(t, refreshed.ImplicitGrantEnabled, "ImplicitGrantEnabled should not be nil")
    assert.True(t, *refreshed.ImplicitGrantEnabled, "ImplicitGrantEnabled should be true")
}

func TestAPIClientOAuth2FlowsPut_ImplicitGrantEnabled_ExplicitDisable(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Start with implicit explicitly enabled
    implicitEnabled := true
    client := &models.Client{
        ClientIdentifier:         "flows-implicit-off-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        IsPublic:                 true,
        AuthorizationCodeEnabled: true,
        ImplicitGrantEnabled:     &implicitEnabled,
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Explicitly disable implicit flow
    implicitDisabled := false
    reqBody := api.UpdateClientOAuth2FlowsRequest{
        AuthorizationCodeEnabled: true,
        ImplicitGrantEnabled:     &implicitDisabled,
    }
    apiURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/oauth2-flows"
    resp := makeAPIRequest(t, "PUT", apiURL, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var updateResp api.UpdateClientResponse
    err = json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)

    // DB should have false
    refreshed, err := database.GetClientById(nil, client.Id)
    assert.NoError(t, err)
    assert.NotNil(t, refreshed.ImplicitGrantEnabled, "ImplicitGrantEnabled should not be nil")
    assert.False(t, *refreshed.ImplicitGrantEnabled, "ImplicitGrantEnabled should be false")
}

func TestAPIClientOAuth2FlowsPut_PKCERequired_TriState(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := &models.Client{
        ClientIdentifier:         "flows-pkce-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        IsPublic:                 true,
        AuthorizationCodeEnabled: true,
        PKCERequired:             nil, // Initially use global
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    apiURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/oauth2-flows"

    // Test 1: Explicitly require PKCE
    pkceRequired := true
    reqBody := api.UpdateClientOAuth2FlowsRequest{
        AuthorizationCodeEnabled: true,
        PKCERequired:             &pkceRequired,
    }
    resp := makeAPIRequest(t, "PUT", apiURL, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    refreshed, err := database.GetClientById(nil, client.Id)
    assert.NoError(t, err)
    assert.NotNil(t, refreshed.PKCERequired)
    assert.True(t, *refreshed.PKCERequired, "PKCERequired should be true")

    // Test 2: Explicitly make PKCE optional
    pkceOptional := false
    reqBody2 := api.UpdateClientOAuth2FlowsRequest{
        AuthorizationCodeEnabled: true,
        PKCERequired:             &pkceOptional,
    }
    resp2 := makeAPIRequest(t, "PUT", apiURL, accessToken, reqBody2)
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusOK, resp2.StatusCode)

    refreshed2, err := database.GetClientById(nil, client.Id)
    assert.NoError(t, err)
    assert.NotNil(t, refreshed2.PKCERequired)
    assert.False(t, *refreshed2.PKCERequired, "PKCERequired should be false")

    // Test 3: Use global setting (nil)
    reqBody3 := api.UpdateClientOAuth2FlowsRequest{
        AuthorizationCodeEnabled: true,
        PKCERequired:             nil,
    }
    resp3 := makeAPIRequest(t, "PUT", apiURL, accessToken, reqBody3)
    defer func() { _ = resp3.Body.Close() }()
    assert.Equal(t, http.StatusOK, resp3.StatusCode)

    refreshed3, err := database.GetClientById(nil, client.Id)
    assert.NoError(t, err)
    assert.Nil(t, refreshed3.PKCERequired, "PKCERequired should be nil (use global)")
}

func TestAPIClientOAuth2FlowsPut_ImplicitOnly_NoAuthCode(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create client with only implicit flow (no auth code)
    implicitEnabled := true
    client := &models.Client{
        ClientIdentifier:         "flows-implicit-only-" + strings.ToLower(gofakeit.LetterN(8)),
        Enabled:                  true,
        IsPublic:                 true,
        AuthorizationCodeEnabled: false,
        ImplicitGrantEnabled:     &implicitEnabled,
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Update to keep implicit enabled, auth code disabled
    reqBody := api.UpdateClientOAuth2FlowsRequest{
        AuthorizationCodeEnabled: false,
        ImplicitGrantEnabled:     &implicitEnabled,
    }
    apiURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/oauth2-flows"
    resp := makeAPIRequest(t, "PUT", apiURL, accessToken, reqBody)
    defer func() { _ = resp.Body.Close() }()

    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var updateResp api.UpdateClientResponse
    err = json.NewDecoder(resp.Body).Decode(&updateResp)
    assert.NoError(t, err)
    assert.False(t, updateResp.Client.AuthorizationCodeEnabled)

    // DB should reflect settings
    refreshed, err := database.GetClientById(nil, client.Id)
    assert.NoError(t, err)
    assert.False(t, refreshed.AuthorizationCodeEnabled)
    assert.NotNil(t, refreshed.ImplicitGrantEnabled)
    assert.True(t, *refreshed.ImplicitGrantEnabled)
}
