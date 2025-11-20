package integrationtests

import (
    "bytes"
    "encoding/json"
    "net/http"
    neturl "net/url"
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

// Test GET /api/v1/admin/clients/{id}/permissions success
func TestAPIClientPermissions_Get_Success(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create client
    client := &models.Client{ClientIdentifier: "api-perm-get-" + gofakeit.LetterN(6), Enabled: true, IsPublic: true}
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Create resource + permission and assign to client
    resource := createResource(t)
    perm := createPermission(t, resource.Id)
    err = database.CreateClientPermission(nil, &models.ClientPermission{ClientId: client.Id, PermissionId: perm.Id})
    assert.NoError(t, err)

    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    var apiResp api.GetClientPermissionsResponse
    err = json.NewDecoder(resp.Body).Decode(&apiResp)
    assert.NoError(t, err)
    assert.Equal(t, client.Id, apiResp.Client.Id)
    assert.GreaterOrEqual(t, len(apiResp.Permissions), 1)

    // Ensure the expected permission is present
    found := false
    for _, p := range apiResp.Permissions {
        if p.Id == perm.Id && p.Resource.Id == resource.Id {
            found = true
            break
        }
    }
    assert.True(t, found, "expected assigned permission in response")
}

// Test GET error cases: invalid id and not found
func TestAPIClientPermissions_Get_Errors(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Invalid format id
    url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/abc/permissions"
    resp := makeAPIRequest(t, "GET", url, accessToken, nil)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Invalid client ID format", errResp.Error.Message)

    // Not found
    url = config.GetAuthServer().BaseURL + "/api/v1/admin/clients/9999999/permissions"
    resp = makeAPIRequest(t, "GET", url, accessToken, nil)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusNotFound, resp.StatusCode)
    errResp = api.ErrorResponse{}
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Client not found", errResp.Error.Message)
}

// Test PUT /api/v1/admin/clients/{id}/permissions add and remove
func TestAPIClientPermissions_Put_AddRemove(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create confidential client with client-credentials enabled
    secret := gofakeit.Password(true, true, true, true, false, 32)
    settings, err := database.GetSettingsById(nil, 1)
    assert.NoError(t, err)
    enc, err := encryption.EncryptText(secret, settings.AESEncryptionKey)
    assert.NoError(t, err)

    client := &models.Client{
        ClientIdentifier:         "api-perm-put-" + strings.ToLower(gofakeit.LetterN(6)),
        Enabled:                  true,
        ClientCredentialsEnabled: true,
        IsPublic:                 false,
        ClientSecretEncrypted:    enc,
    }
    err = database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Create two permissions
    res := createResource(t)
    p1 := createPermission(t, res.Id)
    p2 := createPermission(t, res.Id)

    // First assign p1 (with a duplicate in request to test de-dup)
    putURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
    reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{p1.Id, p1.Id}}
    resp := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusOK, resp.StatusCode)
    var success api.SuccessResponse
    err = json.NewDecoder(resp.Body).Decode(&success)
    assert.NoError(t, err)
    assert.True(t, success.Success)

    // Verify only p1 is assigned
    cps, err := database.GetClientPermissionsByClientId(nil, client.Id)
    assert.NoError(t, err)
    assert.Equal(t, 1, len(cps))
    assert.Equal(t, p1.Id, cps[0].PermissionId)

    // Now replace with p2 (should remove p1 and add p2)
    reqBody = api.UpdateClientPermissionsRequest{PermissionIds: []int64{p2.Id}}
    resp2 := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusOK, resp2.StatusCode)

    cps, err = database.GetClientPermissionsByClientId(nil, client.Id)
    assert.NoError(t, err)
    assert.Equal(t, 1, len(cps))
    assert.Equal(t, p2.Id, cps[0].PermissionId)
}

// Test PUT idempotence when sending the same set of permissions
func TestAPIClientPermissions_Put_Idempotent(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create confidential client with client-credentials enabled
    secret := gofakeit.Password(true, true, true, true, false, 32)
    settings, err := database.GetSettingsById(nil, 1)
    assert.NoError(t, err)
    enc, err := encryption.EncryptText(secret, settings.AESEncryptionKey)
    assert.NoError(t, err)

    client := &models.Client{ClientIdentifier: "api-perm-put-same-" + strings.ToLower(gofakeit.LetterN(6)), Enabled: true, ClientCredentialsEnabled: true, IsPublic: false, ClientSecretEncrypted: enc}
    err = database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // Create one permission and assign via PUT
    res := createResource(t)
    p := createPermission(t, res.Id)

    putURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
    reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{p.Id}}
    resp := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusOK, resp.StatusCode)

    // Verify assignment
    cps, err := database.GetClientPermissionsByClientId(nil, client.Id)
    assert.NoError(t, err)
    assert.Equal(t, 1, len(cps))
    assert.Equal(t, p.Id, cps[0].PermissionId)

    // Call PUT again with the same set (no changes expected)
    resp2 := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusOK, resp2.StatusCode)

    // Verify still exactly one assignment, unchanged
    cps, err = database.GetClientPermissionsByClientId(nil, client.Id)
    assert.NoError(t, err)
    assert.Equal(t, 1, len(cps))
    assert.Equal(t, p.Id, cps[0].PermissionId)
}

// Test GET and PUT unauthorized (no access token)
func TestAPIClientPermissions_Unauthorized(t *testing.T) {
    // Create a target client
    client := &models.Client{ClientIdentifier: "api-perm-unauth-" + gofakeit.LetterN(6), Enabled: true, ClientCredentialsEnabled: true, IsPublic: true}
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    // GET without token
    getURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
    httpClient := createHttpClient(t)
    req, _ := http.NewRequest("GET", getURL, nil)
    resp, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
    buf := new(bytes.Buffer)
    _, _ = buf.ReadFrom(resp.Body)
    assert.Equal(t, "Access token required", strings.TrimSpace(buf.String()))

    // PUT without token
    putURL := getURL
    reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{}}
    bodyBytes, _ := json.Marshal(&reqBody)
    req, _ = http.NewRequest("PUT", putURL, bytes.NewBuffer(bodyBytes))
    resp2, err := httpClient.Do(req)
    assert.NoError(t, err)
    defer func() { _ = resp2.Body.Close() }()
    assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
    buf2 := new(bytes.Buffer)
    _, _ = buf2.ReadFrom(resp2.Body)
    assert.Equal(t, "Access token required", strings.TrimSpace(buf2.String()))
}

// Test PUT validation: client-credentials disabled
func TestAPIClientPermissions_Put_ClientCredentialsDisabled(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    client := &models.Client{
        ClientIdentifier:         "api-perm-put-nocc-" + gofakeit.LetterN(6),
        Enabled:                  true,
        ClientCredentialsEnabled: false,
        IsPublic:                 true,
    }
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    res := createResource(t)
    p := createPermission(t, res.Id)

    putURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
    reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{p.Id}}
    resp := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Client permissions can only be configured when client credentials flow is enabled", errResp.Error.Message)
}

// Test PUT validation: system-level client rejected
func TestAPIClientPermissions_Put_SystemLevelRejected(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Find admin console system-level client id
    listURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
    listResp := makeAPIRequest(t, "GET", listURL, accessToken, nil)
    defer func() { _ = listResp.Body.Close() }()
    assert.Equal(t, http.StatusOK, listResp.StatusCode)
    var clients api.GetClientsResponse
    err := json.NewDecoder(listResp.Body).Decode(&clients)
    assert.NoError(t, err)

    var sysId int64
    for _, c := range clients.Clients {
        if c.ClientIdentifier == constants.AdminConsoleClientIdentifier {
            sysId = c.Id
            break
        }
    }
    if sysId == 0 {
        t.Skip("system-level client not found")
    }

    // Attempt to update permissions
    putURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysId, 10) + "/permissions"
    reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{999999}}
    resp := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Equal(t, "Trying to edit a system level client", errResp.Error.Message)
}

// Test PUT validation: permission id not found
func TestAPIClientPermissions_Put_PermissionNotFound(t *testing.T) {
    accessToken, _ := createAdminClientWithToken(t)

    // Create client with client-credentials enabled
    client := &models.Client{ClientIdentifier: "api-perm-put-noperm-" + gofakeit.LetterN(6), Enabled: true, ClientCredentialsEnabled: true, IsPublic: true}
    err := database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

    putURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
    reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{99999999}}
    resp := makeAPIRequest(t, "PUT", putURL, accessToken, &reqBody)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusNotFound, resp.StatusCode)

    var errResp api.ErrorResponse
    _ = json.NewDecoder(resp.Body).Decode(&errResp)
    assert.Contains(t, strings.ToLower(errResp.Error.Message), "permission not found")
}

// Test PUT insufficient scope (expect 403)
func TestAPIClientPermissions_Put_InsufficientScope(t *testing.T) {
    // Create a client with only authserver:userinfo scope
    httpClient := createHttpClient(t)

    // Create confidential client and grant userinfo
    secret := gofakeit.Password(true, true, true, true, false, 32)
    settings, err := database.GetSettingsById(nil, 1)
    assert.NoError(t, err)
    enc, err := encryption.EncryptText(secret, settings.AESEncryptionKey)
    assert.NoError(t, err)

    client := &models.Client{ClientIdentifier: "api-perm-put-scope-" + strings.ToLower(gofakeit.LetterN(6)), Enabled: true, ClientCredentialsEnabled: true, IsPublic: false, ClientSecretEncrypted: enc}
    err = database.CreateClient(nil, client)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, client.Id) }()

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

    // Get token with only userinfo scope
    destUrl := config.GetAuthServer().BaseURL + "/auth/token/"
    formData := neturl.Values{
        "grant_type":    {"client_credentials"},
        "client_id":     {client.ClientIdentifier},
        "client_secret": {secret},
        "scope":         {constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier},
    }
    data := postToTokenEndpoint(t, httpClient, destUrl, formData)
    tok, ok := data["access_token"].(string)
    assert.True(t, ok)
    assert.NotEmpty(t, tok)

    // Create target client to update
    target := &models.Client{ClientIdentifier: "api-perm-put-target-" + gofakeit.LetterN(6), Enabled: true, ClientCredentialsEnabled: true, IsPublic: true}
    err = database.CreateClient(nil, target)
    assert.NoError(t, err)
    defer func() { _ = database.DeleteClient(nil, target.Id) }()

    putURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/permissions"
    reqBody := api.UpdateClientPermissionsRequest{PermissionIds: []int64{}}
    // Intentionally use insufficient scope token
    resp := makeAPIRequest(t, "PUT", putURL, tok, &reqBody)
    defer func() { _ = resp.Body.Close() }()
    assert.Equal(t, http.StatusForbidden, resp.StatusCode)
    // Plain text error from middleware
    buf := new(bytes.Buffer)
    _, _ = buf.ReadFrom(resp.Body)
    assert.Equal(t, "Insufficient scope", strings.TrimSpace(buf.String()))
}
