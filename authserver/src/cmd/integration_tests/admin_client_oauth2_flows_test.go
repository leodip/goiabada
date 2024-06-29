package integrationtests

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminClientOAuth2Flows_Get_ClientNotFound(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/9999/oauth2-flows"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAdminClientOAuth2Flows_Get(t *testing.T) {
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
		ClientIdentifier:         "c-" + gofakeit.UUID(),
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

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/oauth2-flows"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("input[name=authCodeEnabled]:checked")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name=clientCredentialsEnabled]:checked")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientOAuth2Flows_Post_SystemLevelClient(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	client, err := database.GetClientById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/oauth2-flows"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
	assert.True(t, client.IsSystemLevelClient())
}

func TestAdminClientOAuth2Flows_Post_Case1(t *testing.T) {
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
		ClientIdentifier:         "c-" + gofakeit.UUID(),
		ClientSecretEncrypted:    clientSecretEncrypted,
		Description:              "This client is going to be deleted",
		Enabled:                  true,
		ConsentRequired:          true,
		IsPublic:                 false,
		AuthorizationCodeEnabled: false,
		ClientCredentialsEnabled: false,
	}

	err = database.CreateClient(nil, newClient)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/oauth2-flows"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"authCodeEnabled":          {"on"},
		"clientCredentialsEnabled": {"on"},
		"gorilla.csrf.Token":       {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 302, resp.StatusCode)

	client, err := database.GetClientById(nil, newClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, client.AuthorizationCodeEnabled)
	assert.True(t, client.ClientCredentialsEnabled)

	redirectLocation := resp.Header.Get("Location")
	assert.Equal(t, lib.GetBaseUrl()+"/admin/clients/"+strconv.FormatInt(newClient.Id, 10)+"/oauth2-flows", redirectLocation)
}

func TestAdminClientOAuth2Flows_Post_Case2(t *testing.T) {
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
		ClientIdentifier:         "c-" + gofakeit.UUID(),
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

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/oauth2-flows"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"authCodeEnabled":          {""},
		"clientCredentialsEnabled": {""},
		"gorilla.csrf.Token":       {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 302, resp.StatusCode)

	client, err := database.GetClientById(nil, newClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.False(t, client.AuthorizationCodeEnabled)
	assert.False(t, client.ClientCredentialsEnabled)

	redirectLocation := resp.Header.Get("Location")
	assert.Equal(t, lib.GetBaseUrl()+"/admin/clients/"+strconv.FormatInt(newClient.Id, 10)+"/oauth2-flows", redirectLocation)
}
