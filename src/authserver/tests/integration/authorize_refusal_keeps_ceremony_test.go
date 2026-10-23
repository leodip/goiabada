package integration

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A sign-in in progress survives an authorization request the server refuses in the same browser
// (#436). /auth/authorize used to save a fresh auth context before validating anything, so a
// malformed link, opened while the password page was showing, replaced the ceremony behind it:
// the password form then carried the old ceremony id and was refused, and the user had to start
// again. A refused request now writes nothing, so the form posted afterwards completes the first
// ceremony and the client receives its code with the first request's state.
//
// Each row runs in a fresh browser against its own client and user, so no row leans on another's
// session.
func TestAuthorize_ARefusedRequestLeavesTheSignInInProgress(t *testing.T) {
	for _, tc := range []struct {
		name       string
		malformed  func(clientIdentifier, redirectURI string) string
		wantStatus int
	}{
		{
			name: "unknown client_id",
			malformed: func(clientIdentifier, redirectURI string) string {
				return "client_id=no-such-client-" + fake.LetterN(8) +
					"&redirect_uri=" + url.QueryEscape(redirectURI) + "&response_type=code&scope=openid"
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "unregistered redirect_uri",
			malformed: func(clientIdentifier, redirectURI string) string {
				return "client_id=" + clientIdentifier +
					"&redirect_uri=" + url.QueryEscape("https://unregistered.example/cb") +
					"&response_type=code&scope=openid"
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "response_mode=jwt",
			malformed: func(clientIdentifier, redirectURI string) string {
				return "client_id=" + clientIdentifier +
					"&redirect_uri=" + url.QueryEscape(redirectURI) +
					"&response_type=code&scope=openid&response_mode=jwt"
			},
			wantStatus: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, redirectUri := createLevel1Client(t, false)
			user, password := createCeremonyUser(t)
			httpClient := createHttpClient(t)

			requestState := fake.LetterN(16)
			destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
				"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
				"&response_type=code" +
				"&code_challenge_method=S256" +
				"&code_challenge=" + fake.LetterN(43) +
				"&scope=" + url.QueryEscape("openid profile") +
				"&state=" + requestState +
				"&nonce=" + fake.LetterN(8)

			resp := loadPage(t, httpClient, destUrl)
			redirectLocation := assertRedirect(t, resp, "/auth/level1")
			_ = resp.Body.Close()

			resp = loadPage(t, httpClient, redirectLocation)
			pwdUrl := assertRedirect(t, resp, "/auth/pwd")
			_ = resp.Body.Close()

			// The password page is read in full now and kept, because the form is posted only after
			// the malformed request, and what the user posts is what this page rendered.
			pwdPage := loadPage(t, httpClient, pwdUrl)
			require.Equal(t, http.StatusOK, pwdPage.StatusCode)
			pwdBody, err := io.ReadAll(pwdPage.Body)
			require.NoError(t, err)
			_ = pwdPage.Body.Close()
			pwdPage.Body = io.NopCloser(bytes.NewReader(pwdBody))

			resp = loadPage(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/authorize/?"+
				tc.malformed(client.ClientIdentifier, redirectUri.URI))
			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			assert.Empty(t, resp.Header.Get("Location"), "the refusal is a page, not a redirect")
			_ = resp.Body.Close()

			resp = authenticateWithPassword(t, httpClient, pwdUrl, pwdPage, user.Email, password)
			redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
			_ = resp.Body.Close()

			resp = loadPage(t, httpClient, redirectLocation)
			redirectLocation = assertRedirect(t, resp, "/auth/completed")
			_ = resp.Body.Close()

			resp = loadPage(t, httpClient, redirectLocation)
			redirectLocation = assertRedirect(t, resp, "/auth/issue")
			_ = resp.Body.Close()

			resp = loadPage(t, httpClient, redirectLocation)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, http.StatusFound, resp.StatusCode)
			assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), redirectUri.URI),
				"the code goes to the first request's client, got %q", resp.Header.Get("Location"))
			_, state := getCodeAndStateFromUrl(t, resp)
			assert.Equal(t, requestState, state)
		})
	}
}

// A sign-in in progress survives an authorization request the server answers at once with an error
// in the same browser (#246). /auth/authorize used to remove the browser's sign-in before it
// answered such a request, so a link that was not even a valid sign-in ended the one in progress,
// and a page receiving the error redirect could send the browser back to repeat it. A request
// answered at once now stores nothing and removes nothing, on the interactive route and as a
// prompt=none refusal alike, so the form posted afterwards completes the first sign-in and its
// client receives the code with the first request's state.
func TestAuthorize_AnErrorAnsweredAtOnceLeavesTheSignInInProgress(t *testing.T) {
	t.Run("a prompt=none request answered login_required", func(t *testing.T) {
		client, redirectUri := createLevel1Client(t, false)
		user, password := createCeremonyUser(t)
		httpClient := createHttpClient(t)

		requestState := fake.LetterN(16)
		pwdUrl, pwdPage := walkToPasswordPageKept(t, httpClient,
			authorizeUrlFor(client, redirectUri, "openid profile", requestState))

		// The same client asking silently from another tab. The browser holds no user session, so
		// the answer is login_required, at the client's redirect URI.
		silentState := fake.LetterN(16)
		resp := loadPage(t, httpClient,
			authorizeUrlFor(client, redirectUri, "openid", silentState)+"&prompt=none")
		require.Equal(t, http.StatusFound, resp.StatusCode)
		assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), redirectUri.URI),
			"the refusal goes to the client, got %q", resp.Header.Get("Location"))
		errorCode, _, state := getErrorFromUrl(t, resp)
		assert.Equal(t, "login_required", errorCode)
		assert.Equal(t, silentState, state)
		_ = resp.Body.Close()

		resp = authenticateWithPassword(t, httpClient, pwdUrl, pwdPage, user.Email, password)
		redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
		_ = resp.Body.Close()

		resp = loadPage(t, httpClient, redirectLocation)
		redirectLocation = assertRedirect(t, resp, "/auth/completed")
		_ = resp.Body.Close()

		resp = loadPage(t, httpClient, redirectLocation)
		redirectLocation = assertRedirect(t, resp, "/auth/issue")
		_ = resp.Body.Close()

		assertCodeIssuedFor(t, loadPage(t, httpClient, redirectLocation), redirectUri.URI, requestState)
	})

	t.Run("an interactive request answered unauthorized_client", func(t *testing.T) {
		client, redirectUri := createConsentClient(t)
		user, password := createCeremonyUser(t)
		httpClient := createHttpClient(t)

		// The sign-in reaches the consent screen, by which point /auth/completed has given the browser
		// a valid user session, so a refused request in this browser is answered at once rather than
		// deferred until a password is entered (RFC 9700 4.11.2).
		requestState := fake.LetterN(16)
		resp := loadPage(t, httpClient, authorizeUrlFor(client, redirectUri, "openid profile", requestState))
		redirectLocation := assertRedirect(t, resp, "/auth/level1")
		_ = resp.Body.Close()
		resp = loadPage(t, httpClient, redirectLocation)
		pwdUrl := assertRedirect(t, resp, "/auth/pwd")
		_ = resp.Body.Close()
		pwdPage := loadPage(t, httpClient, pwdUrl)
		resp = authenticateWithPassword(t, httpClient, pwdUrl, pwdPage, user.Email, password)
		_ = pwdPage.Body.Close()
		redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
		_ = resp.Body.Close()
		resp = loadPage(t, httpClient, redirectLocation)
		redirectLocation = assertRedirect(t, resp, "/auth/completed")
		_ = resp.Body.Close()
		resp = loadPage(t, httpClient, redirectLocation)
		consentUrl := assertRedirect(t, resp, "/auth/consent")
		_ = resp.Body.Close()
		consentPage := keptPage(t, loadPage(t, httpClient, consentUrl))

		// Another client's request, refused by redirect at once: its code flow is off.
		disabledClient, _, _ := newCodeFlowDisabledClient(t)
		resp = loadPage(t, httpClient, codeFlowDisabledAuthorizeURL(disabledClient.ClientIdentifier))
		require.Equal(t, http.StatusFound, resp.StatusCode)
		assert.Equal(t,
			deferralRedirectURI+"?error=unauthorized_client"+
				"&error_description="+url.QueryEscape(codeFlowDisabledDescription)+
				"&state="+deferralStateEscaped+issParam(t),
			resp.Header.Get("Location"))
		_ = resp.Body.Close()

		resp = postConsent(t, httpClient, consentUrl, consentPage, []int{0, 1})
		redirectLocation = assertRedirect(t, resp, "/auth/issue")
		_ = resp.Body.Close()

		assertCodeIssuedFor(t, loadPage(t, httpClient, redirectLocation), redirectUri.URI, requestState)
	})
}

// walkToPasswordPageKept starts the authorization at authorizeUrl and walks it to the password page,
// returning that page's URL and the page itself read in full, because its form is posted only after
// another request, and what the user posts is what this page rendered.
func walkToPasswordPageKept(t *testing.T, httpClient *http.Client, authorizeUrl string) (string, *http.Response) {
	t.Helper()

	resp := loadPage(t, httpClient, authorizeUrl)
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()

	resp = loadPage(t, httpClient, redirectLocation)
	pwdUrl := assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()

	return pwdUrl, keptPage(t, loadPage(t, httpClient, pwdUrl))
}

// keptPage reads a 200 page in full and closes its connection, leaving the body readable for the
// form posted from it later.
func keptPage(t *testing.T, page *http.Response) *http.Response {
	t.Helper()

	require.Equal(t, http.StatusOK, page.StatusCode)
	body, err := io.ReadAll(page.Body)
	require.NoError(t, err)
	_ = page.Body.Close()
	page.Body = io.NopCloser(bytes.NewReader(body))
	return page
}

// assertCodeIssuedFor asserts /auth/issue answered the first request's client with a code and that
// request's state, and closes the response.
func assertCodeIssuedFor(t *testing.T, resp *http.Response, redirectURI string, wantState string) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), redirectURI),
		"the code goes to the first request's client, got %q", resp.Header.Get("Location"))
	_, state := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, wantState, state)
}
