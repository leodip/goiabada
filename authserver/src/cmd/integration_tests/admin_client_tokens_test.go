package integrationtests

import (
	"net/url"
	"strconv"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminClientTokens_Get_ClientNotFound(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/9999/tokens"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAdminClientTokens_Get(t *testing.T) {
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
		ClientIdentifier:                        "to-be-deleted-" + strconv.Itoa(gofakeit.Number(1000, 9999)),
		ClientSecretEncrypted:                   clientSecretEncrypted,
		Description:                             "This client is going to be deleted",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		DefaultAcrLevel:                         enums.AcrLevel3,
		TokenExpirationInSeconds:                100,
		RefreshTokenOfflineIdleTimeoutInSeconds: 200,
		RefreshTokenOfflineMaxLifetimeInSeconds: 300,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingOn.String(),
	}

	err = database.CreateClient(nil, newClient)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/tokens"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("input[name=tokenExpirationInSeconds]")
	assert.Equal(t, 1, elem.Length())
	assert.Equal(t, "100", elem.AttrOr("value", ""))

	elem = doc.Find("input[name=refreshTokenOfflineIdleTimeoutInSeconds]")
	assert.Equal(t, 1, elem.Length())
	assert.Equal(t, "200", elem.AttrOr("value", ""))

	elem = doc.Find("input[name=refreshTokenOfflineMaxLifetimeInSeconds]")
	assert.Equal(t, 1, elem.Length())
	assert.Equal(t, "300", elem.AttrOr("value", ""))

	elem = doc.Find("input[name=includeOpenIDConnectClaimsInAccessToken][value=on]")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientTokens_Post(t *testing.T) {
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
		ClientIdentifier:                        "to-be-deleted-" + strconv.Itoa(gofakeit.Number(1000, 9999)),
		ClientSecretEncrypted:                   clientSecretEncrypted,
		Description:                             "This client is going to be deleted",
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		DefaultAcrLevel:                         enums.AcrLevel3,
		TokenExpirationInSeconds:                100,
		RefreshTokenOfflineIdleTimeoutInSeconds: 200,
		RefreshTokenOfflineMaxLifetimeInSeconds: 300,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingOn.String(),
	}

	err = database.CreateClient(nil, newClient)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/admin/clients/" + strconv.FormatInt(newClient.Id, 10) + "/tokens"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"tokenExpirationInSeconds":                {"1000"},
		"refreshTokenOfflineIdleTimeoutInSeconds": {"2000"},
		"refreshTokenOfflineMaxLifetimeInSeconds": {"3000"},
		"includeOpenIDConnectClaimsInAccessToken": {"off"},
		"gorilla.csrf.Token":                      {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 302, resp.StatusCode)

	client, err := database.GetClientById(nil, newClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 1000, client.TokenExpirationInSeconds)
	assert.Equal(t, 2000, client.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, 3000, client.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.Equal(t, enums.ThreeStateSettingOff.String(), client.IncludeOpenIDConnectClaimsInAccessToken)
}
