package integrationtests

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminClientDelete_Get_ClientNotFound(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/9999/delete"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAdminClientDelete_Get(t *testing.T) {
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

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/delete"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("div p:contains('Are you sure?')")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("tbody tr td:contains('" + newClient.ClientIdentifier + "')")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("tbody tr td:contains('" + newClient.Description + "')")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("tbody tr td").FilterFunction(func(_ int, s *goquery.Selection) bool {
		return s.Text() == "Confidential"
	})
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("tbody tr td:contains('Authorization code flow with PKCE, client credentials flow')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientDelete_Post_SystemLevelClient(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	client, err := database.GetClientById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(client.Id, 10) + "/delete"
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

func TestAdminClientDelete_Post_ClientIdentifierRequired(t *testing.T) {
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

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/delete"
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

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("div p:contains('Client identifier is required')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientDelete_Post_ClientIdentifierInvalid(t *testing.T) {
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

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/delete"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"clientIdentifier":   {"invalid-client-identifier"},
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

	elem := doc.Find("div p:contains('Client identifier does not match the client being deleted')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientDelete_Post(t *testing.T) {
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
		URI:      "https://example.com",
	}
	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	webOrigin := &entities.WebOrigin{
		ClientId: newClient.Id,
		Origin:   "https://example.com",
	}
	err = database.CreateWebOrigin(nil, webOrigin)
	if err != nil {
		t.Fatal(err)
	}

	resource, err := database.GetResourceByResourceIdentifier(nil, constants.AuthServerResourceIdentifier)
	if err != nil {
		t.Fatal(err)
	}

	permissions, err := database.GetPermissionsByResourceId(nil, resource.Id)
	if err != nil {
		t.Fatal(err)
	}

	var adminSitePerm *entities.Permission
	for idx, permission := range permissions {
		if permission.PermissionIdentifier == constants.AdminWebsitePermissionIdentifier {
			adminSitePerm = &permissions[idx]
			break
		}
	}

	err = database.CreateClientPermission(nil, &entities.ClientPermission{
		ClientId:     newClient.Id,
		PermissionId: adminSitePerm.Id,
	})
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/delete"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"clientIdentifier":   {newClient.ClientIdentifier},
		"gorilla.csrf.Token": {csrf},
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
	assert.Nil(t, client)

	redirectLocation := resp.Header.Get("Location")
	assert.Equal(t, lib.GetBaseUrl()+"/admin/clients", redirectLocation)
}
