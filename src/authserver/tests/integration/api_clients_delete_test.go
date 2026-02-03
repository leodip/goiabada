package integrationtests

import (
	"encoding/json"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// TestAPIClientDelete_Success verifies successful deletion of a non-system client
func TestAPIClientDelete_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a client directly in DB to delete
	client := &models.Client{
		ClientIdentifier: "del-client-" + gofakeit.LetterN(8),
		Description:      "to delete",
		Enabled:          true,
		IsPublic:         true,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)

	// Delete via API
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var success api.SuccessResponse
	err = json.NewDecoder(resp.Body).Decode(&success)
	assert.NoError(t, err)
	assert.True(t, success.Success)

	// Further GET should return 404
	resp2 := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
}

// TestAPIClientDelete_SystemLevelRejected ensures system-level client cannot be deleted
func TestAPIClientDelete_SystemLevelRejected(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Find admin-console-client id via list
	listURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp := makeAPIRequest(t, "GET", listURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var listResp api.GetClientsResponse
	err := json.NewDecoder(resp.Body).Decode(&listResp)
	assert.NoError(t, err)

	var sysId int64
	for _, c := range listResp.Clients {
		if c.ClientIdentifier == "admin-console-client" {
			sysId = c.Id
			break
		}
	}
	if sysId == 0 {
		t.Skip("system-level client not found")
	}

	delURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysId, 10)
	resp2 := makeAPIRequest(t, "DELETE", delURL, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var body map[string]interface{}
	_ = json.NewDecoder(resp2.Body).Decode(&body)
	if body["error"] != nil {
		msg := body["error"].(map[string]interface{})["message"].(string)
		assert.Contains(t, msg, "system level client")
	}
}

// TestAPIClientDelete_NotFoundAndInvalidId covers 404 and 400 branches
func TestAPIClientDelete_NotFoundAndInvalidId(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Not found
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/9999999"
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Invalid id format
	url = config.GetAuthServer().BaseURL + "/api/v1/admin/clients/abc"
	resp = makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Unauthorized
	httpClient := createHttpClient(t)
	req, err := http.NewRequest("DELETE", config.GetAuthServer().BaseURL+"/api/v1/admin/clients/1", nil)
	assert.NoError(t, err)
	resp2, err := httpClient.Do(req)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

// TestAPIClientGetPermissions_IncludesPermissions ensures client-permissions endpoint returns assigned permissions
func TestAPIClientGetPermissions_IncludesPermissions(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a client and assign a permission
	client := &models.Client{
		ClientIdentifier: "perm-client-" + gofakeit.LetterN(8),
		Enabled:          true,
		IsPublic:         true,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	resource := createResource(t)
	perm := createPermission(t, resource.Id)
	err = database.CreateClientPermission(nil, &models.ClientPermission{ClientId: client.Id, PermissionId: perm.Id})
	assert.NoError(t, err)

	// Call GET client permissions by id
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/permissions"
	resp := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var getResp api.GetClientPermissionsResponse
	err = json.NewDecoder(resp.Body).Decode(&getResp)
	assert.NoError(t, err)

	// Expect at least one permission present
	assert.GreaterOrEqual(t, len(getResp.Permissions), 1)
	// Verify identifiers present
	found := false
	for _, p := range getResp.Permissions {
		if p.Id == perm.Id {
			found = true
			break
		}
	}
	assert.True(t, found, "expected assigned permission in client response")
}

// TestAPIClientDelete_InsufficientScope ensures 403 when token lacks admin scope
func TestAPIClientDelete_InsufficientScope(t *testing.T) {
	// inline createClientWithUserinfoScope
	var accessToken string
	var clientWithScope *models.Client

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
	clientWithScope = client
	defer func() { _ = database.DeleteClient(nil, clientWithScope.Id) }()

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
	formData := neturl.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"scope":         {constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)
	tok, ok := data["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, tok)
	accessToken = tok

	// Create a target client to attempt deleting
	target := &models.Client{
		ClientIdentifier: "target-del-" + gofakeit.LetterN(6),
		Enabled:          true,
		IsPublic:         true,
	}
	err = database.CreateClient(nil, target)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, target.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestAPIClientDelete_CascadesLinkedData ensures related data is removed when a client is deleted
func TestAPIClientDelete_CascadesLinkedData(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create client
	client := &models.Client{
		ClientIdentifier: "cascade-client-" + gofakeit.LetterN(6),
		Enabled:          true,
		IsPublic:         true,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)

	// Create permission and assign to client
	resource := createResource(t)
	perm := createPermission(t, resource.Id)
	err = database.CreateClientPermission(nil, &models.ClientPermission{ClientId: client.Id, PermissionId: perm.Id})
	assert.NoError(t, err)

	// Create user and consent to the client
	user := &models.User{Subject: uuid.New(), Enabled: true, Email: gofakeit.Email()}
	err = database.CreateUser(nil, user)
	assert.NoError(t, err)
	consent := &models.UserConsent{ClientId: client.Id, UserId: user.Id, Scope: "openid"}
	err = database.CreateUserConsent(nil, consent)
	assert.NoError(t, err)

	// Delete client via API
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
	resp := makeAPIRequest(t, "DELETE", url, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Assert client permissions removed
	cps, err := database.GetClientPermissionsByClientId(nil, client.Id)
	assert.NoError(t, err)
	assert.True(t, len(cps) == 0)

	// Assert user consent removed
	uc, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	assert.NoError(t, err)
	assert.Nil(t, uc)
}
