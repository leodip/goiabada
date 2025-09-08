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

func TestAPIClientAuthenticationPut_ConfidentialToPublic_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// inline createConfidentialClient
	clientSecret := stringutil.GenerateSecurityRandomString(60)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	enc, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:      "auth-client-" + strings.ToLower(gofakeit.LetterN(10)),
		Enabled:               true,
		ConsentRequired:       false,
		IsPublic:              false,
		ClientSecretEncrypted: enc,
		// Make client credentials enabled to verify it gets disabled when switching to public
		ClientCredentialsEnabled: true,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: true}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify DB updates
	refreshed, err := database.GetClientById(nil, client.Id)
	assert.NoError(t, err)
	assert.NotNil(t, refreshed)
	assert.True(t, refreshed.IsPublic)
	assert.Nil(t, refreshed.ClientSecretEncrypted)
	assert.False(t, refreshed.ClientCredentialsEnabled)
}

func TestAPIClientAuthenticationPut_PublicToConfidential_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := createPublicClient(t)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	newSecret := stringutil.GenerateSecurityRandomString(60)
	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: newSecret}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify DB updates
	refreshed, err := database.GetClientById(nil, client.Id)
	assert.NoError(t, err)
	assert.NotNil(t, refreshed)
	assert.False(t, refreshed.IsPublic)
	assert.NotNil(t, refreshed.ClientSecretEncrypted)

	// Detail GET should include decrypted secret matching newSecret
	detailURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
	resp2 := makeAPIRequest(t, "GET", detailURL, accessToken, nil)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var getResp api.GetClientResponse
	err = json.NewDecoder(resp2.Body).Decode(&getResp)
	assert.NoError(t, err)
	assert.Equal(t, newSecret, getResp.Client.ClientSecret)
}

func TestAPIClientAuthenticationPut_InvalidSecret_TooShort(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := createPublicClient(t)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	// Too short secret
	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: "abc123"}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != nil {
		msg := body["error"].(map[string]interface{})["message"].(string)
		assert.Equal(t, "Invalid client secret. Please generate a new one.", msg)
	}
}

func TestAPIClientAuthenticationPut_InvalidSecret_BadChars(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := createPublicClient(t)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	// 60 chars but includes an invalid '!'
	bad := strings.Repeat("A", 59) + "!"
	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: bad}
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != nil {
		msg := body["error"].(map[string]interface{})["message"].(string)
		assert.Equal(t, "Invalid client secret. Please generate a new one.", msg)
	}
}

func TestAPIClientAuthenticationPut_NotFoundAndInvalidId(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Not found
	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/999999/authentication"
	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientAuthenticationRequest{IsPublic: true})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var nf map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&nf)
	if nf["error"] != nil {
		msg := nf["error"].(map[string]interface{})["message"].(string)
		assert.Contains(t, msg, "Client not found")
	}

	// Invalid id
	url2 := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/abc/authentication"
	resp2 := makeAPIRequest(t, "PUT", url2, accessToken, api.UpdateClientAuthenticationRequest{IsPublic: true})
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var body map[string]interface{}
	_ = json.NewDecoder(resp2.Body).Decode(&body)
	if body["error"] != nil {
		msg := body["error"].(map[string]interface{})["message"].(string)
		assert.Contains(t, msg, "Invalid client ID")
	}
}

func TestAPIClientAuthenticationPut_SystemLevelClientRejected(t *testing.T) {
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

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysId, 10) + "/authentication"
	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: true}
	resp2 := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var body map[string]interface{}
	_ = json.NewDecoder(resp2.Body).Decode(&body)
	if body["error"] != nil {
		msg := body["error"].(map[string]interface{})["message"].(string)
		assert.Contains(t, msg, "system level client")
	}
}

func TestAPIClientAuthenticationPut_InsufficientScope(t *testing.T) {
	// Create a token with only auth-server:userinfo scope
	clientSecret := stringutil.GenerateSecurityRandomString(60)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	enc, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "inscope-auth-" + strings.ToLower(gofakeit.LetterN(8)),
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
	target := createPublicClient(t)
	defer func() { _ = database.DeleteClient(nil, target.Id) }()

	url := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/authentication"
	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: stringutil.GenerateSecurityRandomString(60)}
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// helper to create a public client directly in DB
func createPublicClient(t *testing.T) *models.Client {
	t.Helper()
	client := &models.Client{
		ClientIdentifier:         "pub-client-" + strings.ToLower(gofakeit.LetterN(10)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
	}
	err := database.CreateClient(nil, client)
	assert.NoError(t, err)
	return client
}
