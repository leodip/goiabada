package integration

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
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
