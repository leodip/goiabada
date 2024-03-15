package integrationtests

import (
	"strconv"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminClientSettings_Get_ClientNotFound(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/9999/settings"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAdminClientSettings_Get(t *testing.T) {

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
		Description:              "This client is going to be deleted " + strconv.Itoa(gofakeit.Number(1000, 9999)),
		Enabled:                  true,
		ConsentRequired:          true,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          "urn:goiabada:pwd:otp_mandatory",
	}

	err = database.CreateClient(nil, newClient)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/settings"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("input[name=clientIdentifier]")
	assert.Equal(t, 1, elem.Length())
	assert.Equal(t, newClient.ClientIdentifier, elem.AttrOr("value", ""))

	elem = doc.Find("input[name=description]")
	assert.Equal(t, 1, elem.Length())
	assert.Equal(t, newClient.Description, elem.AttrOr("value", ""))

	doc.Find("select[name=defaultAcrLevel] option").Each(func(i int, s *goquery.Selection) {
		if _, exists := s.Attr("selected"); exists {
			assert.Equal(t, newClient.DefaultAcrLevel.String(), s.AttrOr("value", ""))
		}
	})

	elem = doc.Find("input[name=enabled][checked]")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name=consentRequired][checked]")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientSettings_Post_SystemLevelClient(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/1/settings"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := map[string][]string{
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatalf("Error posting to %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAdminClientSettings_Post_ClientIdentifierAlreadyExists(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/3/settings"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := map[string][]string{
		"clientIdentifier":   {"test-client-1"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatalf("Error posting to %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("div.text-error p:contains('The client identifier is already in use')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientSettings_Post(t *testing.T) {
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
		DefaultAcrLevel:          enums.AcrLevel3,
	}

	err = database.CreateClient(nil, newClient)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/settings"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := map[string][]string{
		"clientIdentifier":   {"new-name-" + strconv.Itoa(gofakeit.Number(1000, 9999))},
		"description":        {"New description " + strconv.Itoa(gofakeit.Number(1000, 9999))},
		"defaultAcrLevel":    {enums.AcrLevel1.String()},
		"enabled":            {"off"},
		"consentRequired":    {"off"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatalf("Error posting to %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 302, resp.StatusCode)

	client, err := database.GetClientById(nil, newClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, formData["clientIdentifier"][0], client.ClientIdentifier)
	assert.Equal(t, formData["description"][0], client.Description)
	assert.Equal(t, enums.AcrLevel1, client.DefaultAcrLevel)
	assert.Equal(t, false, client.Enabled)
	assert.Equal(t, false, client.ConsentRequired)
}
