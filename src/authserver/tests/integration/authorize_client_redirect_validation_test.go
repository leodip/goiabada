package integrationtests

import (
	"net/http"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func TestAuthorize_ValidateClientAndRedirectURI_ClientIdIsMissing(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/"

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "The client_id parameter is missing.", errorMsg)
}

func TestAuthorize_ValidateClientAndRedirectURI_ClientDoesNotExist(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=does_not_exist"

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Invalid client_id parameter. The client does not exist.", errorMsg)
}

func TestAuthorize_ValidateClientAndRedirectURI_ClientIsDisabled(t *testing.T) {
	client := &models.Client{
		ClientIdentifier: "test-client-" + gofakeit.LetterN(8),
		Enabled:          false,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Invalid client_id parameter. The client is disabled.", errorMsg)
}

func TestAuthorize_ValidateClientAndRedirectURI_ClientDoesNotSupportTheAuthorizationCodeFlow(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: false,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Invalid client_id parameter. The client does not support the authorization code flow.", errorMsg)
}

func TestAuthorize_ValidateClientAndRedirectURI_RedirectURIIsMissing(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "The redirect_uri parameter is missing.", errorMsg)
}

func TestAuthorize_ValidateClientAndRedirectURI_ClientDoesNotHaveRedirectURI(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier + "&redirect_uri=" + gofakeit.URL()

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Invalid redirect_uri parameter. The client does not have this redirect URI registered.", errorMsg)
}
