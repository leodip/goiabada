package integrationtests

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file owns decisions 10, 11 and 12: an error response to a client that registered itself is
// not delivered by redirecting the user's browser to that client's host. It is shown to the user
// instead, on a page with nothing on it to press, and the authorization ends there.
//
// RFC 9700 section 4.11.2 lists both attacks it closes. Attack 2 needs a user to decline; attack 1
// needs nothing but a link with an invalid scope in it, which is why the control sits inside
// redirToClientWithError rather than on the decline path (#108).

// The English copy for the interstitial, written out rather than read back through i18n.T: this
// test process never loads the catalogs, so T would answer with the key itself and every assertion
// below would pass against a page that rendered nothing.
const (
	interstitialTitle      = "You have not been sent anywhere"
	interstitialClosing    = "The request stops here."
	interstitialUnverified = "It registered itself with this server, so nobody here has checked who it is"
)

// assertRedirectWasWithheld asserts the response is the interstitial and that it is a dead end.
//
// The absence of a way out is asserted rather than inferred from the status code, because that is
// the property decision 14 chose and the one a later change would most plausibly undo: a Continue
// button, a link to the client, or a meta refresh would each turn this page back into the redirect
// it exists to withhold.
func assertRedirectWasWithheld(t *testing.T, resp *http.Response, expectedDestination string) {
	t.Helper()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "the browser must not be sent anywhere")

	doc := parseHTMLResponse(t, resp)
	body := doc.Text()

	assert.Contains(t, body, interstitialTitle)
	assert.Contains(t, body, expectedDestination,
		"the page names where the client wanted to send the user")
	assert.Contains(t, body, interstitialClosing)

	assert.Equal(t, 0, doc.Find("form").Length(), "a dead end has no form to submit")
	assert.Equal(t, 0, doc.Find("button").Length(), "and no button to press")
	assert.Equal(t, 0, doc.Find("a").Length(), "and no link to follow")
	assert.Equal(t, 0, doc.Find(`meta[http-equiv="refresh"]`).Length(), "and does not redirect itself")
}

// TestDCR_Refusal_DeclinedConsentIsNotDeliveredByRedirect is RFC 9700 4.11.2 attack 2. A user who
// is shown an application they do not recognise and correctly refuses it was, before this, sent
// straight to that application's site by this server.
func TestDCR_Refusal_DeclinedConsentIsNotDeliveredByRedirect(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	httpClient, _, _, _ := walkDCRClientToConsentScreen(t, "Refusing Portal")

	consentURL := config.GetAuthServer().BaseURL + "/auth/consent"
	consentPage := loadPage(t, httpClient, consentURL)

	// No consents selected sends btnCancel, which is the user declining.
	resp := postConsent(t, httpClient, consentURL, consentPage, []int{})
	_ = consentPage.Body.Close()
	defer func() { _ = resp.Body.Close() }()

	// walkDCRClientToConsentScreen registers at https://dcr-app.example.com/callback.
	assertRedirectWasWithheld(t, resp, "dcr-app.example.com")

	body := parseHTMLResponse(t, resp).Text()
	assert.Contains(t, body, "Refusing Portal", "the page names the client by what it claims to be")
	assert.Contains(t, body, interstitialUnverified,
		"and repeats that the claim is the client's own")
}

// TestDCR_Refusal_AdministratorClientStillRedirects is the case that fails if the trust signal is
// dropped and the interstitial is applied to every client. An administrator registered this client
// and vetted its redirect URI, which is precisely the risk-assessment input RFC 9700 4.11.2 names,
// so its error response is delivered exactly as it was before this change.
func TestDCR_Refusal_AdministratorClientStillRedirects(t *testing.T) {
	client, redirectUri := createConsentClient(t)
	user, password := createCeremonyUser(t)
	httpClient := createHttpClient(t)

	consentPage := navigateToConsentScreen(t, httpClient, client, user, password, redirectUri.URI)
	consentURL := config.GetAuthServer().BaseURL + "/auth/consent"

	resp := postConsent(t, httpClient, consentURL, consentPage, []int{})
	_ = consentPage.Body.Close()
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode,
		"an administrator-created client's error response is still delivered by redirect")

	errorCode, _, _ := getErrorFromUrl(t, resp)
	assert.Equal(t, "access_denied", errorCode)

	location := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(location, redirectUri.URI),
		"and it goes to the client's own registered URI: %s", location)
}

// TestDCR_Refusal_InvalidScopeIsNotDeliveredByRedirect is RFC 9700 4.11.2 attack 1, and it is
// probe/unauthenticated_error_redirect_test.go inverted. That probe sent one GET from a browser
// holding no cookies, with an invalid scope, and watched the server answer
// "302 Location: https://attacker.example.com/callback?error=invalid_scope" with nobody logged in
// and nothing rendered.
//
// It is also why the control lives in redirToClientWithError rather than on the decline path: this
// attack is strictly cheaper than waiting for a refusal, so a control placed only there is walked
// around by sending this link instead.
func TestDCR_Refusal_InvalidScopeIsNotDeliveredByRedirect(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	const redirectURI = "https://dcr-attack-scope.example.com/callback"
	client := registerDCRClient(t, "Payroll Portal", redirectURI)

	// A browser with no cookies at all. Nobody is logged in.
	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(authorizeURLWithScope(client.ClientIdentifier, redirectURI, "openid nonsense", ""))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assertRedirectWasWithheld(t, resp, "dcr-attack-scope.example.com")
}

// TestDCR_Refusal_UnresolvedClientIsNotRedirectedEither pins the fail-safe. The trust decision is
// about where the redirect URI came from, so a client the handler cannot resolve is the untrusted
// case rather than an exempt one: "we could not find out" is not an answer that justifies using it.
//
// Deleting the client mid-ceremony is what makes that reachable here, and it is not contrived: an
// administrator removing a client while somebody is part-way through authorizing it produces
// exactly this. The client is administrator-created on purpose, so the case fails if the nil
// disjunct is dropped rather than passing on the provenance test instead (#108, decision 14).
func TestDCR_Refusal_UnresolvedClientIsNotRedirectedEither(t *testing.T) {
	client, redirectUri := createConsentClient(t)
	user, password := createCeremonyUser(t)
	httpClient := createHttpClient(t)

	consentPage := navigateToConsentScreen(t, httpClient, client, user, password, redirectUri.URI)
	consentURL := config.GetAuthServer().BaseURL + "/auth/consent"

	// The ceremony still holds the redirect URI, the state and everything else the redirect would
	// be built from. Only the client row is gone, which is all provenance is read from.
	require.NoError(t, database.DeleteClient(nil, client.Id))

	resp := postConsent(t, httpClient, consentURL, consentPage, []int{})
	_ = consentPage.Body.Close()
	defer func() { _ = resp.Body.Close() }()

	parsedRedirect, err := url.Parse(redirectUri.URI)
	require.NoError(t, err)
	assertRedirectWasWithheld(t, resp, parsedRedirect.Host)
}

// TestDCR_Refusal_SilentRequestStillRedirects is the case that fails if the OIDC Core 3.1.2.1
// exemption is lost. It deliberately takes the error at a site inside HandleAuthorizeGet, where
// the ceremony has not yet been given a validated prompt: silence has to be read off the raw
// request parameter there or a silent renewal iframe is answered with a page it cannot read,
// which "MUST NOT display any authentication or consent user interface pages" forbids.
//
// TestPromptNone_DCRClient_NoConsent_ReturnsConsentRequired owns the other half, the sites where
// the ceremony does hold the prompt and is what must be read instead.
func TestDCR_Refusal_SilentRequestStillRedirects(t *testing.T) {
	enableDCR(t)
	defer disableDCR(t)

	const redirectURI = "https://dcr-silent-scope.example.com/callback"
	client := registerDCRClient(t, "Silent Portal", redirectURI)

	httpClient := createHttpClient(t)
	requestState := gofakeit.LetterN(8)

	resp, err := httpClient.Get(authorizeURLWithScope(client.ClientIdentifier, redirectURI,
		"openid nonsense", requestState) + "&prompt=none")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode,
		"a silent request is answered by redirect even for a self-registered client")

	errorCode, _, state := getErrorFromUrl(t, resp)
	assert.Equal(t, "invalid_scope", errorCode)
	assert.Equal(t, requestState, state)
}

// authorizeURLWithScope builds an authorization request that is well formed apart from whatever the
// caller puts in the scope.
func authorizeURLWithScope(clientIdentifier string, redirectURI string, scope string, state string) string {
	if state == "" {
		state = gofakeit.LetterN(8)
	}
	return config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + clientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + state +
		"&nonce=" + gofakeit.LetterN(8)
}
