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

func TestAdminClientAuthentication_Get(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	client, err := database.GetClientById(nil, 2)
	if err != nil {
		t.Fatal(err)
	}

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	clientSecretDecrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("input[name='clientSecret']")
	assert.Equal(t, 1, elem.Length())
	assert.Equal(t, clientSecretDecrypted, elem.AttrOr("value", ""))
}

func TestAdminClientAuthentication_Get_SystemLevelClient(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	client, err := database.GetClientById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	clientSecretDecrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("input[name='clientSecret']")
	assert.Equal(t, 1, elem.Length())
	assert.Equal(t, clientSecretDecrypted, elem.AttrOr("value", ""))

	elem = doc.Find("p:contains('The settings for this system-level client cannot be changed')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientAuthentication_Get_ClientDoesNotExist(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/99999/authentication"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAdminClientAuthentication_Post_SystemLevelClient(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	client, err := database.GetClientById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
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

func TestAdminClientAuthentication_Post_Confidential_ClientSecretLengthInvalid(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	client, err := database.GetClientById(nil, 2)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"publicConfidential": {"confidential"},
		"clientSecret":       {"123"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("div.text-error p:contains('Invalid client secret. Please generate a new one')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientAuthentication_Post_Confidential(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	client, err := database.GetClientById(nil, 2)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/authentication"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	newClientSecret := lib.GenerateSecureRandomString(60)

	formData := url.Values{
		"publicConfidential": {"confidential"},
		"clientSecret":       {newClientSecret},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 302, resp.StatusCode)

	redirectLocation := resp.Header.Get("Location")
	assert.Equal(t, lib.GetBaseUrl()+"/admin/clients/"+strconv.FormatInt(client.Id, 10)+"/authentication", redirectLocation)

	resp, err = httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("div.text-success p:contains('Client authentication saved successfully')")
	assert.Equal(t, 1, elem.Length())

	client, err = database.GetClientById(nil, 2)
	if err != nil {
		t.Fatal(err)
	}

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	clientSecretDecrypted, err := lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, newClientSecret, clientSecretDecrypted)
}

func TestAdminClientAuthentication_Post_Public(t *testing.T) {
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

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/authentication"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"publicConfidential": {"public"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 302, resp.StatusCode)

	redirectLocation := resp.Header.Get("Location")
	assert.Equal(t, lib.GetBaseUrl()+"/admin/clients/"+strconv.FormatInt(newClient.Id, 10)+"/authentication", redirectLocation)

	resp, err = httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("div.text-success p:contains('Client authentication saved successfully')")
	assert.Equal(t, 1, elem.Length())

	client, err := database.GetClientById(nil, newClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, client.IsPublic)
	assert.Nil(t, client.ClientSecretEncrypted)
	assert.False(t, client.ClientCredentialsEnabled)
}

func TestAdminClientAuthentication_Get_GenerateNewSecret(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/generate-new-secret"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	data := unmarshalToMap(t, resp)
	assert.Len(t, data["NewSecret"], 60)
}
