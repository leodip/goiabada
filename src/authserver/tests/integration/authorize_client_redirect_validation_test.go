package integrationtests

import (
	"net/http"
	"net/url"
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

// TestAuthorize_ValidateClientAndRedirectURI_RedirectURIIsNotAbsolute owns the RFC 6749
// section 4.1.2.1 pin for the absolute-URI gate: "If the request fails due to a missing,
// invalid, or mismatching redirection URI [...] the authorization server SHOULD inform the
// resource owner of the error and MUST NOT automatically redirect the user-agent to the
// invalid redirection URI."
//
// The URI is REGISTERED on the client and then requested, which is what makes this case
// about the gate rather than about the matcher: with the gate removed the value matches its
// own registration exactly, validation succeeds, and the ceremony goes on to emit it as a
// protocol-relative Location that hands the authorization code to evil.example.
//
// Asserting the absence of a Location header is the reason this lives at the integration
// tier rather than in the validator's unit table. createHttpClient sets CheckRedirect to
// http.ErrUseLastResponse, so a 302 would be observed here rather than followed, and no
// request to evil.example is ever attempted by the test itself (#122).
func TestAuthorize_ValidateClientAndRedirectURI_RedirectURIIsNotAbsolute(t *testing.T) {
	const nonAbsoluteURI = "//evil.example/cb"

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	err = database.CreateRedirectURI(nil, &models.RedirectURI{ClientId: client.Id, URI: nonAbsoluteURI})
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(nonAbsoluteURI)

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "the authorization server must not redirect to an invalid redirection URI")

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Invalid redirect_uri parameter. The redirect URI must be an absolute URI: a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host.", errorMsg)
}
