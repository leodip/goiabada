package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminClientRedirectURIs_Get_ClientNotFound(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/9999/redirect-uris"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAdminClientRedirectURIs_Get(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientSecretEncrypted, err := lib.EncryptText(lib.GenerateRandomNumbers(60), settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	newClient := &entities.Client{
		ClientIdentifier:         "to-be-deleted-" + strconv.Itoa(gofakeit.Number(1000, 9999)),
		ClientSecretEncrypted:    clientSecretEncrypted,
		Description:              "This client is going to be deleted",
		Enabled:                  true,
		ConsentRequired:          true,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
	}

	err = database.CreateClient(nil, newClient)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &entities.RedirectURI{
		ClientId: newClient.Id,
		URI:      "https://example1.com",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri = &entities.RedirectURI{
		ClientId: newClient.Id,
		URI:      "https://example2.com",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/redirect-uris"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %s", err)
	}

	assert.Equal(t, 200, resp.StatusCode)

	assert.True(t, strings.Contains(string(body), "redirectURIs.push(\"https:\\/\\/example1.com\");"))
	assert.True(t, strings.Contains(string(body), "redirectURIs.push(\"https:\\/\\/example2.com\");"))
}

func TestAdminClientRedirectURIs_Post(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientSecretEncrypted, err := lib.EncryptText(lib.GenerateRandomNumbers(60), settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	newClient := &entities.Client{
		ClientIdentifier:         "to-be-deleted-" + strconv.Itoa(gofakeit.Number(1000, 9999)),
		ClientSecretEncrypted:    clientSecretEncrypted,
		Description:              "This client is going to be deleted",
		Enabled:                  true,
		ConsentRequired:          true,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
	}

	err = database.CreateClient(nil, newClient)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &entities.RedirectURI{
		ClientId: newClient.Id,
		URI:      "https://example1.com",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri = &entities.RedirectURI{
		ClientId: newClient.Id,
		URI:      "https://example2.com",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/redirect-uris"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	destUrl = lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/redirect-uris"

	data := struct {
		ClientId     int64    `json:"clientId"`
		RedirectURIs []string `json:"redirectURIs"`
		Ids          []int64  `json:"ids"`
	}{
		ClientId:     newClient.Id,
		RedirectURIs: []string{"https://example2.com", "https://example3.com"},
		Ids:          []int64{redirectUri.Id, 0},
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("POST", destUrl, strings.NewReader(string(jsonData)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	responseData := unmarshalToMap(t, resp)
	assert.Equal(t, true, responseData["Success"])

	client, err := database.GetClientById(nil, newClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	err = database.ClientLoadRedirectURIs(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 2, len(client.RedirectURIs))
	assert.Equal(t, "https://example2.com", client.RedirectURIs[0].URI)
	assert.Equal(t, "https://example3.com", client.RedirectURIs[1].URI)
}
