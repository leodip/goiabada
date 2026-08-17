package integrationtests

import (
	"net/http"
	"net/url"
	"strings"
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

// The seven assertions above are the regression guard for the English catalog: since #213 the
// refusal page reads its title and its message out of the catalog rather than out of Go literals,
// and those seven prove the sentences survived the move byte for byte.
//
// This is the other half, and it is deliberately one condition rather than seven. Catalog parity
// across locales is proved once by TestCatalog_ParityEnPtBR, and falling back to English on an
// unknown locale is proved once by TestT_UnknownLocaleFallsBackToEnglish, both in src/core/i18n.
// What neither can prove is that the request's ui_locales reaches THIS page, which is the whole
// defect: the page was wired to render whatever it was handed and was handed an English literal.
// Seven Portuguese assertions would be the parity test again, in a slower tier, and would couple
// this file to seven translations.
//
// Both the title and the message are asserted. They fail independently: the title regresses if the
// Go literal comes back, and the message regresses if the handler renders EnglishFallback() instead
// of Localize(), which no English assertion in this file can see.
func TestAuthorize_ValidateClientAndRedirectURI_RendersInTheRequestedLocale(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=does_not_exist&ui_locales=pt-BR"

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

	title := strings.TrimSpace(doc.Find("h1").First().Text())
	assert.Equal(t, "Não foi possível autorizar", title,
		"the refusal page title did not render in pt-BR; ui_locales did not reach it")
	assert.NotEqual(t, "Unable to authorize", title,
		"the refusal page title is still the English literal")

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Parâmetro client_id inválido. O cliente não existe.", errorMsg,
		"the refusal page message did not render in pt-BR; the handler is rendering the English fallback rather than the request locale")
}
