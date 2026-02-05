package integrationtests

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Phase 3: Response Mode Tests
// =============================================================================

func TestPromptNone_Error_QueryModeDefault(t *testing.T) {
	// No session, prompt=none with default response_mode (query)
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	// Error should be in query params (default mode)
	errorCode := redirectURL.Query().Get("error")
	state := redirectURL.Query().Get("state")

	assert.Equal(t, "login_required", errorCode)
	assert.Equal(t, requestState, state)
	// Fragment should be empty
	assert.Empty(t, redirectURL.Fragment)
}

func TestPromptNone_Error_QueryModeExplicit(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&response_mode=query" +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	// Error should be in query params
	errorCode := redirectURL.Query().Get("error")
	state := redirectURL.Query().Get("state")

	assert.Equal(t, "login_required", errorCode)
	assert.Equal(t, requestState, state)
}

func TestPromptNone_Error_FragmentMode(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&response_mode=fragment" +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	// Error should be in fragment
	fragmentValues, err := url.ParseQuery(redirectURL.Fragment)
	if err != nil {
		t.Fatal(err)
	}

	errorCode := fragmentValues.Get("error")
	state := fragmentValues.Get("state")

	assert.Equal(t, "login_required", errorCode)
	assert.Equal(t, requestState, state)
	// Query should be empty or not contain error
	assert.Empty(t, redirectURL.Query().Get("error"))
}

func TestPromptNone_Success_QueryMode(t *testing.T) {
	httpClient, client, redirectUri, _ := createSessionWithAcrLevel1(t)

	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&response_mode=query" +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Follow redirect to /auth/issue
	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	// Code should be in query params
	codeVal := redirectURL.Query().Get("code")
	stateVal := redirectURL.Query().Get("state")

	assert.NotEmpty(t, codeVal, "code should be present in query")
	assert.Equal(t, requestState, stateVal)
	assert.Empty(t, redirectURL.Fragment, "fragment should be empty")
}

func TestPromptNone_Success_FragmentMode(t *testing.T) {
	httpClient, client, redirectUri, _ := createSessionWithAcrLevel1(t)

	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&response_mode=fragment" +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Follow redirect to /auth/issue
	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	// Code should be in fragment
	fragmentValues, err := url.ParseQuery(redirectURL.Fragment)
	if err != nil {
		t.Fatal(err)
	}

	codeVal := fragmentValues.Get("code")
	stateVal := fragmentValues.Get("state")

	assert.NotEmpty(t, codeVal, "code should be present in fragment")
	assert.Equal(t, requestState, stateVal)
	assert.Empty(t, redirectURL.Query().Get("code"), "code should not be in query")
}

func TestPromptNone_Success_FormPostMode(t *testing.T) {
	httpClient, client, redirectUri, _ := createSessionWithAcrLevel1(t)

	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&response_mode=form_post" +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Follow redirect to /auth/issue
	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	// form_post returns HTML page, not a redirect
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body := readResponseBody(t, resp)

	// Should contain a form with the code
	assert.Contains(t, body, "<form")
	assert.Contains(t, body, "name=\"code\"")
	assert.Contains(t, body, "name=\"state\"")
	assert.Contains(t, body, requestState)
}

func TestPromptNone_Error_FormPostMode(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&response_mode=form_post" +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// form_post error returns HTML page with error fields
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body := readResponseBody(t, resp)

	// Should contain a form with error
	assert.Contains(t, body, "<form")
	assert.Contains(t, body, "name=\"error\"")
	assert.Contains(t, body, "login_required")
	assert.Contains(t, body, requestState)
}

// =============================================================================
// Phase 3: State Parameter Tests
// =============================================================================

func TestPromptNone_StateEchoedOnError(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestState := "my-custom-state-" + gofakeit.LetterN(16)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	errorCode, _, state := getErrorFromUrl(t, resp)

	assert.Equal(t, "login_required", errorCode)
	assert.Equal(t, requestState, state, "state should be echoed back exactly")
}

func TestPromptNone_StateEchoedOnSuccess(t *testing.T) {
	httpClient, client, redirectUri, _ := createSessionWithAcrLevel1(t)

	requestState := "success-state-" + gofakeit.LetterN(16)
	requestNonce := gofakeit.LetterN(8)
	requestCodeChallenge := gofakeit.LetterN(43)
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.NotEmpty(t, codeVal)
	assert.Equal(t, requestState, stateVal, "state should be echoed back exactly")
}

func TestPromptNone_NoStateInRequest(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestCodeChallenge := gofakeit.LetterN(43)
	// No state parameter
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	errorCode := redirectURL.Query().Get("error")
	state := redirectURL.Query().Get("state")

	assert.Equal(t, "login_required", errorCode)
	assert.Empty(t, state, "state should be empty when not provided in request")
}

func TestPromptNone_EmptyStateInRequest(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	httpClient := createHttpClient(t)

	requestCodeChallenge := gofakeit.LetterN(43)
	// Empty state parameter
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" +
		"&prompt=none"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	errorCode := redirectURL.Query().Get("error")
	state := redirectURL.Query().Get("state")

	assert.Equal(t, "login_required", errorCode)
	assert.Empty(t, state, "state should be empty when empty in request")
}
