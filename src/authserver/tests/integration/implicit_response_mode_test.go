package integration

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The implicit flow's response mode, over HTTP (#231, decision 15). A request for a response type
// that returns tokens may ask for the fragment, for form_post, or for nothing, and never for the
// query: OAuth 2.0 Multiple Response Type Encoding Practices section 3 says of id_token that "the
// query encoding MUST NOT be used", and OAuth 2.0 Form Post Response Mode section 4 says it is safe
// to return the parameters whose default is the fragment using form_post.
//
// Before, form_post was advertised by discovery and refused for these response types, and an
// explicit query was refused with the refusal itself written into the query.

// implicitModeAuthorizeURL is an implicit request whose response mode is the one thing a test varies.
func implicitModeAuthorizeURL(client *models.Client, redirectURI string, responseType string,
	responseMode string, state string, nonce string) string {

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&response_type=" + url.QueryEscape(responseType) +
		"&scope=" + url.QueryEscape("openid") +
		"&state=" + url.QueryEscape(state)
	if nonce != "" {
		destUrl += "&nonce=" + url.QueryEscape(nonce)
	}
	if responseMode != "" {
		destUrl += "&response_mode=" + responseMode
	}
	return destUrl
}

// signInToIssue walks a whole sign-in, asserting every hop, and returns the response /auth/issue
// produced, which the caller closes. It is the ceremony the longhand tests in implicit_flow_test.go
// walk, written once for the cases here.
func signInToIssue(t *testing.T, httpClient *http.Client, destUrl string, user *models.User, password string) *http.Response {
	t.Helper()

	resp, err := httpClient.Get(destUrl)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	return loadPage(t, httpClient, redirectLocation)
}

// formInputs reads a form_post response: the form's action and every hidden input by name. The page
// is what an RP's user agent receives, and it posts these fields to the action.
func formInputs(t *testing.T, resp *http.Response) (action string, inputs map[string]string) {
	t.Helper()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)

	form := doc.Find("form")
	require.Equal(t, 1, form.Length(), "the page is one auto-submitting form")
	assert.Equal(t, "post", strings.ToLower(form.AttrOr("method", "")))

	inputs = map[string]string{}
	doc.Find("input[type='hidden']").Each(func(_ int, input *goquery.Selection) {
		inputs[input.AttrOr("name", "")] = input.AttrOr("value", "")
	})
	return form.AttrOr("action", ""), inputs
}

// TestImplicitFlow_ResponseModeFormPost_PostsTheTokens is the whole ceremony for a request that
// used to be refused: a form the browser posts to the client, carrying the tokens the fragment would
// have carried, and nothing that would let an intermediary keep it.
func TestImplicitFlow_ResponseModeFormPost_PostsTheTokens(t *testing.T) {
	enableImplicitFlowGlobally(t)

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)

	requestState := fake.LetterN(16)
	requestNonce := fake.LetterN(16)

	resp := signInToIssue(t, createHttpClient(t),
		implicitModeAuthorizeURL(client, redirectUri.URI, "id_token token", "form_post", requestState, requestNonce),
		user, password)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode, "form_post answers with a page, not a redirect")
	assert.Empty(t, resp.Header.Get("Location"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"),
		"the page holds the tokens, and Form Post Response Mode section 2 forbids storing it")
	assert.Equal(t, "no-cache", resp.Header.Get("Pragma"))

	action, inputs := formInputs(t, resp)
	assert.Equal(t, redirectUri.URI, action)
	assert.NotEmpty(t, inputs["access_token"])
	assert.Equal(t, "Bearer", inputs["token_type"])
	assert.NotEmpty(t, inputs["expires_in"])
	assert.NotEmpty(t, inputs["id_token"])
	assert.Equal(t, requestState, inputs["state"])
	assert.NotContains(t, inputs, "code", "an implicit response carries no authorization code")
	assert.NotContains(t, inputs, "refresh_token", "the implicit flow never issues a refresh token")
	assert.NotContains(t, inputs, "error")

	// The tokens are the ones the fragment carries: the ID token names the user and echoes the nonce.
	parts := strings.Split(inputs["id_token"], ".")
	require.Len(t, parts, 3, "id_token is a JWT")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	assert.Contains(t, string(payload), requestNonce, "the ID token echoes the request's nonce")
	assert.Contains(t, string(payload), user.Subject, "the ID token names the user who signed in")
	assert.Equal(t, 3, len(strings.Split(inputs["access_token"], ".")), "access_token is a JWT")
}

// The parameters follow the response type, as the fragment's do: each type's form carries the tokens
// that type returns and no others.
func TestImplicitFlow_ResponseModeFormPost_CarriesTheTokensOfTheResponseType(t *testing.T) {
	enableImplicitFlowGlobally(t)

	for _, tc := range []struct {
		name         string
		responseType string
		present      []string
		absent       []string
	}{
		{name: "token", responseType: "token",
			present: []string{"access_token", "token_type", "expires_in"}, absent: []string{"id_token"}},
		{name: "id_token", responseType: "id_token",
			present: []string{"id_token"}, absent: []string{"access_token", "token_type", "expires_in"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, redirectUri := createImplicitFlowClient(t, nil)
			user, password := createTestUserForImplicit(t)

			resp := signInToIssue(t, createHttpClient(t),
				implicitModeAuthorizeURL(client, redirectUri.URI, tc.responseType, "form_post", fake.LetterN(8), fake.LetterN(16)),
				user, password)
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			_, inputs := formInputs(t, resp)
			for _, name := range tc.present {
				assert.NotEmpty(t, inputs[name], "%s is part of a %s response", name, tc.responseType)
			}
			for _, name := range tc.absent {
				assert.NotContains(t, inputs, name, "%s is not part of a %s response", name, tc.responseType)
			}
		})
	}
}

// The fragment stays the answer for a request that names it and for one that names nothing, and
// neither is touched by the form_post branch: the keep cases of decision 15.
func TestImplicitFlow_ResponseModeFragmentAndAbsent_AreStillDeliveredInTheFragment(t *testing.T) {
	enableImplicitFlowGlobally(t)

	for _, mode := range []string{"", "fragment"} {
		t.Run("response_mode="+mode, func(t *testing.T) {
			client, redirectUri := createImplicitFlowClient(t, nil)
			user, password := createTestUserForImplicit(t)

			requestState := fake.LetterN(16)
			resp := signInToIssue(t, createHttpClient(t),
				implicitModeAuthorizeURL(client, redirectUri.URI, "token", mode, requestState, ""),
				user, password)
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusFound, resp.StatusCode)
			assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), redirectUri.URI+"#"),
				"the tokens are in the fragment")
			tokens := getTokensFromFragment(t, resp)
			assert.NotEmpty(t, tokens["access_token"])
			assert.Equal(t, requestState, tokens["state"])
		})
	}
}

// An explicit query is the one mode a request for tokens may not name, and its refusal is delivered
// in the fragment, where an implicit client reads its responses. The browser here already holds a
// session, so the refusal is answered at once.
func TestImplicitFlow_ResponseModeQuery_IsRefusedInTheFragment(t *testing.T) {
	enableImplicitFlowGlobally(t)

	client, redirectUri := createImplicitFlowClient(t, nil)
	requestState := fake.LetterN(16)

	resp, err := createAuthenticatedHttpClient(t).Get(
		implicitModeAuthorizeURL(client, redirectUri.URI, "token", "query", requestState, ""))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(location, redirectUri.URI+"#"), "the refusal is in the fragment: %s", location)
	assert.NotContains(t, location, "?", "nothing may be written into the query component")

	errorCode, errorDescription, state := getErrorFromFragment(t, resp)
	assert.Equal(t, "invalid_request", errorCode)
	assert.Contains(t, errorDescription, "response_mode=query")
	assert.Equal(t, requestState, state)
}

// The same refusal from a browser with no session: it is parked, the visitor signs in, and it is
// delivered from /auth/level1completed in the fragment as well, so both routes agree (RFC 9700
// section 4.11.2 makes the deferral the rule for an unauthenticated browser).
func TestImplicitFlow_ResponseModeQuery_IsRefusedInTheFragmentAfterLogin(t *testing.T) {
	enableImplicitFlowGlobally(t)

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)
	requestState := fake.LetterN(16)

	resp := driveDeferral(t, createHttpClient(t),
		implicitModeAuthorizeURL(client, redirectUri.URI, "token", "query", requestState, ""), user, password)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	assert.True(t, strings.HasPrefix(location, redirectUri.URI+"#"), "the refusal is in the fragment: %s", location)
	assert.NotContains(t, location, "?")

	errorCode, _, state := getErrorFromFragment(t, resp)
	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, requestState, state)
}

// An error for an implicit request that asked for form_post is answered in the form as well: both
// specifications say the response comes back in the mode the request named. The scope is refused
// after the sign-in, from the parked deferral, which is the path that used to end in the fragment or
// the query whatever the mode.
func TestImplicitFlow_ResponseModeFormPost_AnErrorIsAnsweredInTheForm(t *testing.T) {
	enableImplicitFlowGlobally(t)

	client, redirectUri := createImplicitFlowClient(t, nil)
	user, password := createTestUserForImplicit(t)
	requestState := fake.LetterN(16)

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&response_mode=form_post" +
		"&scope=not_a_valid_scope" +
		"&state=" + url.QueryEscape(requestState)

	resp := driveDeferral(t, createHttpClient(t), destUrl, user, password)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	action, inputs := formInputs(t, resp)
	assert.Equal(t, redirectUri.URI, action)
	assert.Equal(t, "invalid_scope", inputs["error"])
	assert.Equal(t, requestState, inputs["state"])
	assert.NotContains(t, inputs, "access_token", "an error response carries no token")
}

// Silent renewal, the use an SPA has for prompt=none: a browser holding a session and a request for
// form_post is answered at /auth/issue with the form, the same page the interactive sign-in gets.
func TestPromptNone_ImplicitFormPost(t *testing.T) {
	enableImplicitFlowGlobally(t)

	httpClient, _, _, _ := createSessionWithAcrLevel1(t)
	client, redirectUri := createImplicitClientForPromptTests(t)

	requestState := fake.LetterN(8)
	destUrl := implicitModeAuthorizeURL(client, redirectUri.URI, "token", "form_post", requestState, "") +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	action, inputs := formInputs(t, resp)
	assert.Equal(t, redirectUri.URI, action)
	assert.NotEmpty(t, inputs["access_token"])
	assert.Equal(t, requestState, inputs["state"])
}
