package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/securerandom"
	"github.com/stretchr/testify/assert"
)

func TestAPIClientAuthenticationPut_ConfidentialToPublic_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// inline createConfidentialClient
	clientSecret := securerandom.String(60)
	enc, err := dataCipher.Encrypt(clientSecret)
	assert.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:      "auth-client-" + strings.ToLower(fake.LetterN(10)),
		Enabled:               true,
		ConsentRequired:       false,
		IsPublic:              false,
		ClientSecretEncrypted: enc,
		// Make client credentials enabled to verify it gets disabled when switching to public
		ClientCredentialsEnabled: true,
	}
	err = database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: true}
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify DB updates
	refreshed, err := database.GetClientById(context.Background(), nil, client.Id)
	assert.NoError(t, err)
	assert.NotNil(t, refreshed)
	assert.True(t, refreshed.IsPublic)
	assert.Nil(t, refreshed.ClientSecretEncrypted)
	assert.False(t, refreshed.ClientCredentialsEnabled)
}

func TestAPIClientAuthenticationPut_PublicToConfidential_Success(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := createPublicClient(t)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	newSecret := securerandom.String(60)
	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: newSecret}
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify DB updates
	refreshed, err := database.GetClientById(context.Background(), nil, client.Id)
	assert.NoError(t, err)
	assert.NotNil(t, refreshed)
	assert.False(t, refreshed.IsPublic)
	assert.NotNil(t, refreshed.ClientSecretEncrypted)

	// Detail GET should include decrypted secret matching newSecret
	detailURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
	resp2 := makeAPIRequest(t, "GET", detailURL, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var getResp api.GetClientResponse
	err = json.NewDecoder(resp2.Body).Decode(&getResp)
	assert.NoError(t, err)
	assert.Equal(t, newSecret, getResp.Client.ClientSecret)
}

func TestAPIClientAuthenticationPut_InvalidSecret_TooShort(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := createPublicClient(t)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	// Too short secret
	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: "abc123"}
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error_description"] != nil {
		msg := body["error_description"].(string)
		assert.Equal(t, "Invalid client secret. Please generate a new one.", msg)
	}
}

func TestAPIClientAuthenticationPut_InvalidSecret_BadChars(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	client := createPublicClient(t)
	defer func() { _ = database.DeleteClient(context.Background(), nil, client.Id) }()

	// 60 chars but includes an invalid '!'
	bad := strings.Repeat("A", 59) + "!"
	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: bad}
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error_description"] != nil {
		msg := body["error_description"].(string)
		assert.Equal(t, "Invalid client secret. Please generate a new one.", msg)
	}
}

func TestAPIClientAuthenticationPut_NotFoundAndInvalidId(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Not found
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/999999/authentication"
	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateClientAuthenticationRequest{IsPublic: true})
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	var nf map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&nf)
	if nf["error_description"] != nil {
		msg := nf["error_description"].(string)
		assert.Contains(t, msg, "Client not found")
	}

	// Invalid id
	url2 := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/abc/authentication"
	resp2 := makeAPIRequest(t, "PUT", url2, accessToken, api.UpdateClientAuthenticationRequest{IsPublic: true})
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var body map[string]interface{}
	_ = json.NewDecoder(resp2.Body).Decode(&body)
	if body["error_description"] != nil {
		msg := body["error_description"].(string)
		assert.Contains(t, msg, "Invalid client ID")
	}
}

func TestAPIClientAuthenticationPut_SystemLevelClientAllowed(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Get system-level client from DB so we can save/restore state
	sysClient, err := database.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
	assert.NoError(t, err)
	if sysClient == nil {
		t.Skip("system-level client not found")
	}

	// Save original state for restore
	origIsPublic := sysClient.IsPublic
	origSecretEncrypted := sysClient.ClientSecretEncrypted
	origCCEnabled := sysClient.ClientCredentialsEnabled
	defer func() {
		// Re-fetch to get current DB state, then restore original fields
		c, _ := database.GetClientByClientIdentifier(context.Background(), nil, builtin.AdminConsoleClientIdentifier)
		if c != nil {
			c.IsPublic = origIsPublic
			c.ClientSecretEncrypted = origSecretEncrypted
			c.ClientCredentialsEnabled = origCCEnabled
			_ = database.UpdateClient(context.Background(), nil, c)
		}
	}()

	// Update authentication settings (should succeed for system-level client)
	apiURL := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(sysClient.Id, 10) + "/authentication"
	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: securerandom.String(60)}
	resp := makeAPIRequest(t, "PUT", apiURL, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAPIClientAuthenticationPut_InsufficientScope(t *testing.T) {
	// A valid token whose only scope is one no route grants, so the route answers 403
	accessToken := createClientCredentialsTokenWithoutRouteScope(t)

	// Create a target client to attempt updating
	target := createPublicClient(t)
	defer func() { _ = database.DeleteClient(context.Background(), nil, target.Id) }()

	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(target.Id, 10) + "/authentication"
	reqBody := api.UpdateClientAuthenticationRequest{IsPublic: false, ClientSecret: securerandom.String(60)}
	resp := makeAPIRequest(t, "PUT", url, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// helper to create a public client directly in DB
func createPublicClient(t *testing.T) *record.Client {
	t.Helper()
	client := &record.Client{
		ClientIdentifier:         "pub-client-" + strings.ToLower(fake.LetterN(10)),
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 true,
		AuthorizationCodeEnabled: true,
	}
	err := database.CreateClient(context.Background(), nil, client)
	assert.NoError(t, err)
	return client
}
