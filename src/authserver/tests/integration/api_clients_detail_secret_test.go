package integrationtests

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// Verifies confidential client secret is returned in detail but not in list
func TestAPIClientGet_ConfidentialIncludesSecretInDetailButNotList(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	// Create confidential client with encrypted secret
	clientSecret := gofakeit.Password(true, true, true, true, false, 32)
	settings, err := database.GetSettingsById(nil, 1)
	assert.NoError(t, err)
	enc, err := encryption.EncryptText(clientSecret, settings.AESEncryptionKey)
	assert.NoError(t, err)

	client := &models.Client{
		ClientIdentifier:         "secret-client-" + strings.ToLower(gofakeit.LetterN(8)),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		IsPublic:                 false,
		ClientSecretEncrypted:    enc,
	}
	err = database.CreateClient(nil, client)
	assert.NoError(t, err)
	defer func() { _ = database.DeleteClient(nil, client.Id) }()

	// Detail should include clientSecret
	detailURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients/" + strconv.FormatInt(client.Id, 10)
	resp := makeAPIRequest(t, "GET", detailURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var getResp api.GetClientResponse
	err = json.NewDecoder(resp.Body).Decode(&getResp)
	assert.NoError(t, err)
	assert.Equal(t, client.Id, getResp.Client.Id)
	assert.NotEmpty(t, getResp.Client.ClientSecret)

	// List should not include clientSecret
	listURL := config.GetAuthServer().BaseURL + "/api/v1/admin/clients"
	resp2 := makeAPIRequest(t, "GET", listURL, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var listResp api.GetClientsResponse
	err = json.NewDecoder(resp2.Body).Decode(&listResp)
	assert.NoError(t, err)
	found := false
	for _, c := range listResp.Clients {
		if c.Id == client.Id {
			found = true
			assert.Empty(t, c.ClientSecret)
			break
		}
	}
	assert.True(t, found, "newly created client should be in list")
}
