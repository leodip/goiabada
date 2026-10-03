package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #437 decision 21 (#246), end to end: a POST to /auth/authorize is parked and answered with a 303
// to a GET, and the GET runs the ceremony. There is no real-browser harness in the repository, so
// the browser is emulated at the HTTP level as #246 describes: a cross-site POST arrives WITHOUT the
// browser's SameSite=Lax session cookie, which is a request from a client that holds no jar; the
// GET it is answered with is a top-level navigation and carries the cookie, which is the client
// that holds the browser's jar.

// authorizePostForm is a code-flow request for the client, with prompt appended when set.
func authorizePostForm(client *models.Client, redirectURI, prompt string) url.Values {
	form := url.Values{}
	form.Set("client_id", client.ClientIdentifier)
	form.Set("redirect_uri", redirectURI)
	form.Set("response_type", "code")
	form.Set("code_challenge_method", "S256")
	form.Set("code_challenge", fake.LetterN(43))
	form.Set("scope", "openid profile")
	form.Set("state", fake.LetterN(8))
	form.Set("nonce", fake.LetterN(8))
	if prompt != "" {
		form.Set("prompt", prompt)
	}
	return form
}

// crossSitePost sends the form as a cross-site page would: no cookies, and a foreign Origin, which
// is the trigger for the CSRF 403 the endpoint's exemption (#67) prevents.
func crossSitePost(t *testing.T, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+"/auth/authorize", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://www.certification.openid.net")

	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	return resp
}

// The answer to a POST is a 303 to a GET that carries a handle, and it touches nothing of the
// browser: no cookie is set. A 303 rather than a 302 or 307, because the browser must re-issue the
// request as a GET and drop the body.
func TestAuthorizePost_IsParkedAndAnsweredWithA303TouchingNoCookie(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)

	resp := crossSitePost(t, authorizePostForm(client, redirectUri.URI, ""))
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	parkedAuthorizeLocation(t, resp)
	assert.Empty(t, resp.Header.Values("Set-Cookie"),
		"a cross-site POST carries no session cookie, so a cookie set in its answer would replace the browser's own (#246)")
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"), "the Location carries a live handle")
}

// The scenario #246 describes. A browser holds a session; a cross-site page POSTs an authorization
// request, which arrives without the Lax cookie. Before, the answer began a ceremony and set a new
// cookie over the browser's own, so the browser lost the pointer to its session. Now the POST
// touches nothing, and the GET that follows carries the browser's cookie and finds the session.
func TestAuthorizePost_ASignedInBrowserKeepsItsSessionAndIsSingleSignedOn(t *testing.T) {
	browser, client, redirectUri, _ := createSessionWithAcrLevel1(t)
	baseURL, err := url.Parse(appConfig.AuthServer.BaseURL)
	require.NoError(t, err)
	require.NotEmpty(t, browser.Jar.Cookies(baseURL), "the browser holds a session cookie")

	resp := crossSitePost(t, authorizePostForm(client, redirectUri.URI, ""))
	handleURL := parkedAuthorizeLocation(t, resp)
	_ = resp.Body.Close()
	assert.Empty(t, resp.Header.Values("Set-Cookie"),
		"the answer sets no cookie, so it cannot replace the one the browser holds")

	// The navigation is the browser's own: its cookie goes with it, and the session is reused. A
	// valid session skips the password page and goes to the step-up checks (#246: silent
	// renewal and SSO over POST). Reaching /auth/level1completed at all is what shows the session
	// was found, and it is the browser's original one: the POST left it in place.
	resp = loadPage(t, browser, handleURL)
	defer func() { _ = resp.Body.Close() }()
	assertRedirect(t, resp, "/auth/level1completed")
}

// prompt=none from a signed-in browser issues a code without interaction, over POST: the silent
// renewal an application does with a hidden form. The GET the POST is answered with carries the
// cookie, so the session is found.
func TestAuthorizePost_PromptNoneFromASignedInBrowserIssuesSilently(t *testing.T) {
	browser, client, redirectUri, _ := createSessionWithAcrLevel1(t)

	resp := crossSitePost(t, authorizePostForm(client, redirectUri.URI, "none"))
	handleURL := parkedAuthorizeLocation(t, resp)
	_ = resp.Body.Close()

	resp = loadPage(t, browser, handleURL)
	defer func() { _ = resp.Body.Close() }()
	issueLocation := assertRedirect(t, resp, "/auth/issue")

	resp = loadPage(t, browser, issueLocation)
	defer func() { _ = resp.Body.Close() }()
	redirectURL, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.NotEmpty(t, redirectURL.Query().Get("code"), "a code is issued")
	assert.Empty(t, redirectURL.Query().Get("error"))
}

// The other half: a browser with no session, over POST with prompt=none, is answered login_required
// on the redirect and shown no login page (OIDC Core 3.1.2.3).
func TestAuthorizePost_PromptNoneFromABrowserWithNoSessionIsAnsweredLoginRequired(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	form := authorizePostForm(client, redirectUri.URI, "none")

	resp := crossSitePost(t, form)
	handleURL := parkedAuthorizeLocation(t, resp)
	_ = resp.Body.Close()

	resp = loadPage(t, createHttpClient(t), handleURL)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	errorCode, _, state := getErrorFromUrl(t, resp)
	assert.Equal(t, "login_required", errorCode)
	assert.Equal(t, form.Get("state"), state)
}

// A handle is single use. The GET that consumed it ran the ceremony; the same link again is
// refused on the page, with the one answer every unusable handle gets.
func TestAuthorizeGet_ARequestHandleIsSingleUse(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)

	resp := crossSitePost(t, authorizePostForm(client, redirectUri.URI, ""))
	handleURL := parkedAuthorizeLocation(t, resp)
	_ = resp.Body.Close()

	first := loadPage(t, createHttpClient(t), handleURL)
	defer func() { _ = first.Body.Close() }()
	assertRedirect(t, first, "/auth/level1")

	second := loadPage(t, createHttpClient(t), handleURL)
	defer func() { _ = second.Body.Close() }()
	assert.Equal(t, unusableHandleMessage, refusalPageMessage(t, second))
}

const unusableHandleMessage = "This sign-in link is no longer valid. It may have expired, it may have been used already, " +
	"or it may have been changed. Go back to the application you were signing in to and start again."

// Two browsers following one link at once: exactly one runs the ceremony. The claim is the arbiter,
// and this is the whole request path around it.
func TestAuthorizeGet_TwoRequestsForOneHandleHaveExactlyOneWinner(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)

	resp := crossSitePost(t, authorizePostForm(client, redirectUri.URI, ""))
	handleURL := parkedAuthorizeLocation(t, resp)
	_ = resp.Body.Close()

	const followers = 6
	statuses := make([]int, followers)
	var wg sync.WaitGroup
	for i := 0; i < followers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := createHttpClient(t).Get(handleURL)
			if err != nil {
				return
			}
			_ = r.Body.Close()
			statuses[i] = r.StatusCode
		}()
	}
	wg.Wait()

	winners, refused := 0, 0
	for _, status := range statuses {
		switch status {
		case http.StatusFound:
			winners++
		case http.StatusBadRequest:
			refused++
		}
	}
	assert.Equal(t, 1, winners, "one link, one ceremony: %v", statuses)
	assert.Equal(t, followers-1, refused, "and every other follower is refused on the page: %v", statuses)
}

// A handle beside any other authorization parameter is refused and never merged, and the refusal
// comes BEFORE the handle is consumed: the same handle, sent alone, still runs the ceremony.
func TestAuthorizeGet_ARequestHandleBesideAnotherParameterIsRefusedAndNotConsumed(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)

	resp := crossSitePost(t, authorizePostForm(client, redirectUri.URI, ""))
	handleURL := parkedAuthorizeLocation(t, resp)
	_ = resp.Body.Close()

	beside := loadPage(t, createHttpClient(t), handleURL+"&state=injected")
	defer func() { _ = beside.Body.Close() }()
	assert.Equal(t, unusableHandleMessage, refusalPageMessage(t, beside))

	alone := loadPage(t, createHttpClient(t), handleURL)
	defer func() { _ = alone.Body.Close() }()
	assertRedirect(t, alone, "/auth/level1")

	// A leniency on purpose: a parameter the endpoint does not read, appended by something in
	// front of the server, is ignored as it is everywhere else on this endpoint.
	resp = crossSitePost(t, authorizePostForm(client, redirectUri.URI, ""))
	handleURL = parkedAuthorizeLocation(t, resp)
	_ = resp.Body.Close()
	tagged := loadPage(t, createHttpClient(t), handleURL+"&utm_source=newsletter")
	defer func() { _ = tagged.Body.Close() }()
	assertRedirect(t, tagged, "/auth/level1")
}

// Unknown, malformed and expired handles are one answer: the page says nothing about which it was.
func TestAuthorizeGet_AnUnusableRequestHandleIsRefusedOnThePage(t *testing.T) {
	authorizeURL := appConfig.AuthServer.BaseURL + "/auth/authorize?request_handle="

	// An expired request: a row whose deadline has passed and which the sweep has not reached.
	expiredHandle := fake.LetterN(42) + "A"
	require.NoError(t, database.CreateAuthorizeRequest(context.Background(), nil, &models.AuthorizeRequest{
		HandleHash:  hashutil.HashString(expiredHandle),
		RequestForm: "client_id=whatever",
		ExpiresAt:   time.Now().UTC().Add(-time.Second),
	}))

	for name, handle := range map[string]string{
		"never issued":      fake.LetterN(42) + "A",
		"expired":           expiredHandle,
		"too short":         "abc",
		"empty":             "",
		"not the alphabet":  strings.Repeat("!", 43),
		"one character off": strings.Repeat("A", 42) + "B",
	} {
		t.Run(name, func(t *testing.T) {
			resp := loadPage(t, createHttpClient(t), authorizeURL+url.QueryEscape(handle))
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, unusableHandleMessage, refusalPageMessage(t, resp))
		})
	}
}

// A request the GET would refuse on the page is refused at the POST, on the page, and no handle is
// issued: a POST that could never begin a ceremony is not parked.
func TestAuthorizePost_ARequestThatCanNotBeAddressedIsRefusedWithoutAHandle(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)

	t.Run("a client that does not exist", func(t *testing.T) {
		form := authorizePostForm(client, redirectUri.URI, "")
		form.Set("client_id", "no-such-client-"+fake.LetterN(6))

		resp := crossSitePost(t, form)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "a bad client_id has always answered 200 on the page")
		assert.Empty(t, resp.Header.Get("Location"))
	})

	t.Run("a redirect URI the client did not register", func(t *testing.T) {
		form := authorizePostForm(client, "https://unregistered.example/cb", "")

		resp := crossSitePost(t, form)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Location"), "the redirect is never emitted to an address the client did not register")
	})

	t.Run("a response_mode the server cannot encode", func(t *testing.T) {
		form := authorizePostForm(client, redirectUri.URI, "")
		form.Set("response_mode", "web_message")

		resp := crossSitePost(t, form)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Location"))
	})
}

// The merged query and body of a request can pass MySQL's TEXT ceiling of 65,535 bytes while every
// parameter respects the bounds the endpoint applies, so the parked form has no bound of its own
// (decision 21). A request of 66 KB, its body under the 64 KiB limit and the rest in the query,
// takes the whole trip: parked, stored, read and run as the same request over GET.
//
// The oversized hint is not a valid ID token, so the ceremony refuses it as invalid_request, which
// is delivered after the login. Reaching that refusal, and not the refusal page, is what shows the
// GET read the form whole.
func TestAuthorizePost_AFormPast64KiBTakesTheWholeTrip(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)

	form := authorizePostForm(client, redirectUri.URI, "")
	form.Set("id_token_hint", strings.Repeat("h", 45000))
	acrValues := strings.Repeat("a", 21000)
	body := form.Encode()
	query := url.Values{"acr_values": {acrValues}}.Encode()
	require.Greater(t, len(body)+len(query), 65535, "the fixture must exceed MySQL's TEXT ceiling")
	require.Less(t, len(body), 64<<10, "and its body must be within the body limit")

	req, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+"/auth/authorize?"+query, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	handleURL := parkedAuthorizeLocation(t, resp)
	_ = resp.Body.Close()

	resp = loadPage(t, createHttpClient(t), handleURL)
	defer func() { _ = resp.Body.Close() }()
	assertRedirect(t, resp, "/auth/level1")
}
