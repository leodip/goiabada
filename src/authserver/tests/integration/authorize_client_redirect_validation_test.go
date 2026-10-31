package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorize_ValidateClientAndRedirectURI_ClientIdIsMissing(t *testing.T) {
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/"

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
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=does_not_exist"

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
	assert.Equal(t, "Invalid client_id parameter. The application does not exist.", errorMsg)
}

func TestAuthorize_ValidateClientAndRedirectURI_ClientIsDisabled(t *testing.T) {
	client := &record.Client{
		ClientIdentifier: "test-client-" + fake.LetterN(8),
		Enabled:          false,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier

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
	assert.Equal(t, "Invalid client_id parameter. The application is disabled.", errorMsg)
}

// #573 item 3 turned this refusal around: a client whose code flow is off is no longer answered
// on the page but at its redirect URI, so the request that reaches the page answers only the
// missing redirect_uri, and the code-flow message is gone from the page entirely. The delivery
// to the client is pinned beside the other deferrals, in authorize_deferred_error_test.go.
func TestAuthorize_ValidateClientAndRedirectURI_TheCodeFlowIsNoLongerAPageAnswer(t *testing.T) {
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: false,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier

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
	assert.NotContains(t, errorMsg, "authorization code flow",
		"the code flow refusal must not be rendered on the page anymore (#573)")
}

func TestAuthorize_ValidateClientAndRedirectURI_RedirectURIIsMissing(t *testing.T) {
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier

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
	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier + "&redirect_uri=" + fake.URL()

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
	assert.Equal(t, "Invalid redirect_uri parameter. The application does not have this redirect URI registered.", errorMsg)
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

	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(context.Background(), nil, client)
	if err != nil {
		t.Fatal(err)
	}

	err = database.CreateRedirectURI(context.Background(), nil, &record.RedirectURI{ClientId: client.Id, URI: nonAbsoluteURI})
	if err != nil {
		t.Fatal(err)
	}

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
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
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=does_not_exist&ui_locales=pt-BR"

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
	assert.Equal(t, "Parâmetro client_id inválido. O aplicativo não existe.", errorMsg,
		"the refusal page message did not render in pt-BR; the handler is rendering the English fallback rather than the request locale")
}

// TestAuthorize_ValidateClientAndRedirectURI_StoredPlainHTTPIsRefused pins RFC 9700 section 2.6
// at the authorization endpoint: authorization responses "MUST NOT be transmitted over unencrypted
// network connections". A redirect URI that is plain http off the loopback interface, stored before
// intake began refusing the shape (#575), is refused on the "Unable to authorize" page, and nothing
// is sent to it: no Location, so neither a code nor an error reaches the client (#590). The row is
// inserted directly, since no intake accepts one. It is a complete, valid request otherwise, so the
// refusal is the redirect URI's alone.
func TestAuthorize_ValidateClientAndRedirectURI_StoredPlainHTTPIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name         string
		stored       string
		responseType string
	}{
		{"the authorization code flow", "http://app.example.com/callback", "code"},
		{"an uppercase scheme", "HTTP://app.example.com/callback", "code"},
		{"the implicit flow", "http://app.example.com/callback", "id_token token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			implicitAllowed := true
			client := &record.Client{
				ClientIdentifier:         "test-client-" + fake.LetterN(8),
				Enabled:                  true,
				AuthorizationCodeEnabled: true,
				ImplicitGrantEnabled:     &implicitAllowed,
				DefaultAcrLevel:          record.AcrLevel1,
			}
			require.NoError(t, database.CreateClient(context.Background(), nil, client))
			require.NoError(t, database.CreateRedirectURI(context.Background(), nil,
				&record.RedirectURI{ClientId: client.Id, URI: tc.stored}))

			destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
				"&redirect_uri=" + url.QueryEscape(tc.stored) +
				"&response_type=" + url.QueryEscape(tc.responseType) +
				"&code_challenge_method=S256" +
				"&code_challenge=" + oauth.GeneratePKCECodeChallenge(testCodeVerifier) +
				"&scope=openid" +
				"&state=" + fake.LetterN(8) +
				"&nonce=" + fake.LetterN(8)

			httpClient := createHttpClient(t)
			resp, err := httpClient.Get(destUrl)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Empty(t, resp.Header.Get("Location"), "nothing may be sent to a plain-http redirect URI off loopback")

			doc, err := goquery.NewDocumentFromReader(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "Unable to authorize", strings.TrimSpace(doc.Find("h1").First().Text()))
			assert.Equal(t, "Invalid redirect_uri parameter. The redirect URI must not use plain http on a host other than the loopback interface (127.0.0.1, [::1] or localhost).",
				doc.Find("p#errorMsg").Text())
		})
	}
}

// TestAuthorize_ValidateClientAndRedirectURI_StoredLoopbackHTTPStillReceivesTheCode is the other
// side of that refusal: RFC 8252 section 7.3's loopback exception. A plain-http redirect URI on
// localhost or [::1] runs the whole ceremony and the code arrives at it, so a refusal page, an error
// page or a deferred error would each stop it short of /auth/issue (#590). The port flexibility
// on 127.0.0.1 is TestToken_AuthCode_LoopbackEphemeralPort's.
func TestAuthorize_ValidateClientAndRedirectURI_StoredLoopbackHTTPStillReceivesTheCode(t *testing.T) {
	for _, stored := range []string{"http://localhost:7777/callback", "http://[::1]/callback"} {
		t.Run(stored, func(t *testing.T) {
			client := &record.Client{
				ClientIdentifier:         "test-client-" + fake.LetterN(8),
				Enabled:                  true,
				AuthorizationCodeEnabled: true,
				DefaultAcrLevel:          record.AcrLevel1,
			}
			require.NoError(t, database.CreateClient(context.Background(), nil, client))
			require.NoError(t, database.CreateRedirectURI(context.Background(), nil, &record.RedirectURI{ClientId: client.Id, URI: stored}))

			password := fake.Password(8)
			passwordHashed, err := passwordhash.Hash(password)
			require.NoError(t, err)
			user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: passwordHashed}
			require.NoError(t, database.CreateUser(context.Background(), nil, user))

			requestState := fake.LetterN(8)
			destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
				"&redirect_uri=" + url.QueryEscape(stored) +
				"&response_type=code" +
				"&code_challenge_method=S256" +
				"&code_challenge=" + oauth.GeneratePKCECodeChallenge(testCodeVerifier) +
				"&scope=openid" +
				"&state=" + requestState +
				"&nonce=" + fake.LetterN(8)

			httpClient := createHttpClient(t)
			resp, err := httpClient.Get(destUrl)
			require.NoError(t, err)
			defer func(r *http.Response) { _ = r.Body.Close() }(resp)

			redirectLocation := assertRedirect(t, resp, "/auth/level1")
			resp = loadPage(t, httpClient, redirectLocation)
			defer func(r *http.Response) { _ = r.Body.Close() }(resp)

			redirectLocation = assertRedirect(t, resp, "/auth/pwd")
			resp = loadPage(t, httpClient, redirectLocation)
			defer func(r *http.Response) { _ = r.Body.Close() }(resp)

			resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
			defer func(r *http.Response) { _ = r.Body.Close() }(resp)

			redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
			resp = loadPage(t, httpClient, redirectLocation)
			defer func(r *http.Response) { _ = r.Body.Close() }(resp)

			redirectLocation = assertRedirect(t, resp, "/auth/completed")
			resp = loadPage(t, httpClient, redirectLocation)
			defer func(r *http.Response) { _ = r.Body.Close() }(resp)

			redirectLocation = assertRedirect(t, resp, "/auth/issue")
			resp = loadPage(t, httpClient, redirectLocation)
			defer func(r *http.Response) { _ = r.Body.Close() }(resp)

			require.Equal(t, http.StatusFound, resp.StatusCode)
			location, err := url.Parse(resp.Header.Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, stored, location.Scheme+"://"+location.Host+location.Path,
				"the code goes to the stored loopback http redirect URI")
			code, stateVal := getCodeAndStateFromUrl(t, resp)
			assert.NotEmpty(t, code)
			assert.Equal(t, requestState, stateVal)
		})
	}
}
