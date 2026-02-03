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

// PUT /api/v1/admin/clients/{id}/redirect-uris

func TestAPIClientRedirectURIsPut_Success_AddRemoveAndTrim(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create a confidential client with auth code enabled
	clientSecret := stringutil.GenerateSecurityRandomString(60)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	enc, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:         "redir-succ-" + strings.ToLower(gofakeit.LetterN(8)),
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

	// Seed existing redirect URIs
	uriA := "https://a.example.com/callback"
	uriB := "https://b.example.com/callback"
	err = database.CreateRedirectURI(nil, &models.RedirectURI{ClientId: client.Id, URI: uriA})
	assert.NoError(t, err)
	err = database.CreateRedirectURI(nil, &models.RedirectURI{ClientId: client.Id, URI: uriB})
	assert.NoError(t, err)

	// Desired: keep A (with spaces to test trimming), remove B, add C
	uriC := "https://c.example.com/newcb"
	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"  " + uriA + "  ", uriC}}

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/redirect-uris"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var updateResp api.UpdateClientResponse
	err = json.NewDecoder(resp.Body).Decode(&updateResp)
	assert.NoError(t, err)

	// Response should include exactly A and C after trimming
	got := map[string]bool{}
	for _, ru := range updateResp.Client.RedirectURIs {
		got[ru.URI] = true
	}
	assert.Len(t, updateResp.Client.RedirectURIs, 2)
	assert.True(t, got[uriA])
	assert.True(t, got[uriC])

	// Verify DB reflects the change
	refreshed, err := database.GetClientById(nil, client.Id)
	assert.NoError(t, err)
	err = database.ClientLoadRedirectURIs(nil, refreshed)
	assert.NoError(t, err)
	gotDB := map[string]bool{}
	for _, ru := range refreshed.RedirectURIs {
		gotDB[ru.URI] = true
	}
	assert.Len(t, refreshed.RedirectURIs, 2)
	assert.True(t, gotDB[uriA])
	assert.True(t, gotDB[uriC])
	assert.False(t, gotDB[uriB])
}

func TestAPIClientRedirectURIsPut_AuthCodeDisabledRejected(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := &models.Client{
		ClientIdentifier:         "redir-disabled-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: false,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/redirect-uris"
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

func TestAPIClientRedirectURIsPut_SystemLevelClientRejected(t *testing.T) {
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

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysId, 10) + "/redirect-uris"
	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}}
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

func TestAPIClientRedirectURIsPut_DuplicateAndInvalidURLs(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Auth code enabled client
	client := &models.Client{
		ClientIdentifier:         "redir-vali-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	baseURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/redirect-uris"

	// Duplicate
	reqDup := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://dup.example/cb", "https://dup.example/cb"}}
	resp := makeAPIRequest(t, "PUT", baseURL, accessToken, reqDup)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var bodyDup map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&bodyDup)
	if bodyDup["error"] != nil {
		msg := bodyDup["error"].(map[string]interface{})["message"].(string)
		assert.Equal(t, "Duplicate redirect URIs are not allowed", msg)
	}

	// Invalid URL
	reqInv := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"not-a-url"}}
	resp2 := makeAPIRequest(t, "PUT", baseURL, accessToken, reqInv)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var bodyInv map[string]interface{}
	_ = json.NewDecoder(resp2.Body).Decode(&bodyInv)
	if bodyInv["error"] != nil {
		msg := bodyInv["error"].(map[string]interface{})["message"].(string)
		assert.Equal(t, "Invalid redirect URI: not-a-url", msg)
	}

	// Empty (or whitespace only)
	reqEmpty := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"  "}}
	resp3 := makeAPIRequest(t, "PUT", baseURL, accessToken, reqEmpty)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)
	var bodyEmpty map[string]interface{}
	_ = json.NewDecoder(resp3.Body).Decode(&bodyEmpty)
	if bodyEmpty["error"] != nil {
		msg := bodyEmpty["error"].(map[string]interface{})["message"].(string)
		assert.Equal(t, "Redirect URI cannot be empty", msg)
	}
}

func TestAPIClientRedirectURIsPut_NotFound_InvalidId_InvalidBody_Unauthorized(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Not found
	urlNF := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/999999/redirect-uris"
	resp := makeAPIRequest(t, "PUT", urlNF, accessToken, api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var nf map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&nf)
	if nf["error"] != nil {
		msg := nf["error"].(map[string]interface{})["message"].(string)
		assert.Equal(t, "Client not found", msg)
	}

	// Invalid id (non-numeric)
	urlBad := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/abc/redirect-uris"
	resp2 := makeAPIRequest(t, "PUT", urlBad, accessToken, api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}})
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
		ClientIdentifier:         "redir-bad-body-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err := database.CreateClient(nil, client2)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client2.Id) }()

	urlIB := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client2.Id, 10) + "/redirect-uris"
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

func TestAPIClientRedirectURIsPut_InsufficientScope(t *testing.T) {
	// Create a client with only authserver:userinfo scope
	clientSecret := stringutil.GenerateSecurityRandomString(60)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	enc, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "redir-inscope-" + strings.ToLower(gofakeit.LetterN(8)),
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

	// Create a target client with auth code enabled
	target := &models.Client{
		ClientIdentifier:         "redir-target-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: false,
	}
	err = database.CreateClient(nil, target)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, target.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/redirect-uris"
	reqBody := api.UpdateClientRedirectURIsRequest{RedirectURIs: []string{"https://example.com/cb"}}
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
