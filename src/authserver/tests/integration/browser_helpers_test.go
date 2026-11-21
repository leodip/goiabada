package integration

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
)

func createHTTPClient(t *testing.T) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar: jar,
	}

	// disable follow redirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client.Transport = tr
	return client
}

// ceremonyRedirectStatus is the code a redirect of the sign-in ceremony carries, read from the request
// that produced response: every redirect answering a POST is a 303, which RFC 9700 section 4.12
// recommends after a request that may carry the user's credentials, and every one answering a GET is
// a 302 (#576, decision 6).
func ceremonyRedirectStatus(response *http.Response) int {
	if response.Request != nil && response.Request.Method == http.MethodPost {
		return http.StatusSeeOther
	}
	return http.StatusFound
}

// assertRedirect asserts response is a redirect to location's path, with ceremonyRedirectStatus's
// code, so every flow that follows a Location checks it, and returns its Location.
func assertRedirect(t *testing.T, response *http.Response, location string) string {
	expectedStatus := ceremonyRedirectStatus(response)
	if response.StatusCode != expectedStatus {
		t.Fatalf("Expected status code %d, got %d", expectedStatus, response.StatusCode)
	}

	redirectLocation, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, location, redirectLocation.Path)

	// Every redirect between two ceremony routes names the sign-in it belongs to, so a step is
	// judged by the ceremony it names and a tab of a replaced sign-in cannot act on the newer one
	// (#246 decision 22). Checked here so that every flow test that follows a Location asserts it.
	if ceremonyRoutes[redirectLocation.Path] {
		ceremonyIDs := redirectLocation.Query()[ceremony.QueryParameter]
		if assert.Len(t, ceremonyIDs, 1, "a redirect to %s names exactly one ceremony: %s", location,
			redirectLocation.String()) {
			assert.True(t, ceremony.IsWellFormedID(ceremonyIDs[0]),
				"the ceremony a redirect to %s names is an id: %q", location, ceremonyIDs[0])
		}
		assert.Len(t, redirectLocation.Query(), 1, "a redirect between ceremony routes carries the ceremony and nothing else")
	}

	return redirectLocation.String()
}

// stepURLOfTheSameCeremony is the URL of another step of the ceremony a redirect Location names: the
// route under the base URL, naming the same ceremony. It is what a user reaches by typing a step's
// address, or by going back to one, while still in the sign-in the Location belongs to.
func stepURLOfTheSameCeremony(t *testing.T, location string, path string) string {
	t.Helper()

	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	ceremonyID := parsed.Query().Get(ceremony.QueryParameter)
	if ceremonyID == "" {
		t.Fatalf("the location %q names no ceremony", location)
	}
	return appConfig.AuthServer.BaseURL + path + "?" + url.Values{ceremony.QueryParameter: {ceremonyID}}.Encode()
}

// ceremonyRoutes are the routes of the ceremony between /auth/authorize and /auth/issue, each of
// which is reached by a redirect that names its ceremony.
var ceremonyRoutes = map[string]bool{
	"/auth/level1":          true,
	"/auth/pwd":             true,
	"/auth/level1completed": true,
	"/auth/level2":          true,
	"/auth/otp":             true,
	"/auth/recovery-codes":  true,
	"/auth/completed":       true,
	"/auth/consent":         true,
	"/auth/issue":           true,
}

// followParkedAuthorizePost does what a browser does with the answer to a POST to
// /auth/authorize (#246): the POST was parked and answered with a 303 to a GET carrying
// ?request_handle=<handle>, and the browser navigates there with its own cookies. It returns the
// GET's response and closes the POST's.
func followParkedAuthorizePost(t *testing.T, browser *http.Client, postResponse *http.Response) *http.Response {
	t.Helper()
	handleURL := parkedAuthorizeLocation(t, postResponse)
	_ = postResponse.Body.Close()
	return loadPage(t, browser, handleURL)
}

// parkedAuthorizeLocation asserts a POST to /auth/authorize was answered with the 303 to a GET that
// carries a handle and nothing else, and returns that URL.
func parkedAuthorizeLocation(t *testing.T, postResponse *http.Response) string {
	t.Helper()
	if postResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("Expected status code %d, got %d", http.StatusSeeOther, postResponse.StatusCode)
	}
	location, err := url.Parse(postResponse.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "/auth/authorize", location.Path)
	assert.Len(t, location.Query(), 1, "the redirect carries the handle and nothing else")
	assert.Len(t, location.Query().Get("request_handle"), 43, "a 256 bit handle, unpadded")
	return location.String()
}

func loadPage(t *testing.T, client *http.Client, url string) *http.Response {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// authenticateWithPassword submits the login form. pwdPage is the response that rendered it, and
// the ceremony id is read out of it rather than constructed, so the submission carries what a
// browser on that page would carry (#79).
//
// Where a submission follows a refused one, the page to pass is the refusal's own re-render, which
// is what the user is looking at by then.
func authenticateWithPassword(t *testing.T, client *http.Client, destURL string,
	pwdPage *http.Response, email string, password string) *http.Response {

	formData := url.Values{
		"email":      {email},
		"password":   {password},
		"ceremonyId": {getCeremonyIDFromPage(t, pwdPage)},
	}

	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", destURL, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", destURL)
	request.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// authenticateWithOTP submits the OTP form, verification or enrollment. otpPage is the response
// that rendered it, read the same way authenticateWithPassword reads its own (#79).
func authenticateWithOTP(t *testing.T, client *http.Client, destURL string, otpPage *http.Response,
	otp string) *http.Response {

	formData := url.Values{
		"otp":        {otp},
		"ceremonyId": {getCeremonyIDFromPage(t, otpPage)},
	}

	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", destURL, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", destURL)
	request.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func getOTPSecretFromEnrollmentPage(t *testing.T, response *http.Response) string {
	byteArr, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	response.Body = io.NopCloser(bytes.NewReader(byteArr))
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(byteArr)))
	if err != nil {
		t.Fatal(err)
	}
	secret := doc.Find("#otp-secret")
	if secret.Length() != 1 {
		t.Fatal("expecting to find the element with id 'otp-secret' but it was not found")
	}
	return secret.Text()
}

// getCeremonyIDFromPage reads the hidden ceremony id out of a rendered auth-flow page, so the
// tests post the value the server actually rendered rather than one they made up. A field rename
// on one side alone then fails here instead of passing silently (#79).
//
// The selector is scoped to inside the form, and matching anything other than exactly once is a
// failure. That is the whole point of it: a hidden input placed OUTSIDE the <form> element is not
// submitted by any browser, so every real submission would be refused, while a helper that finds
// the value anywhere on the page and posts it by hand would sail past.
//
// The body is re-buffered, as getOTPSecretFromEnrollmentPage does, so a later reader of the same
// response still sees it.
func getCeremonyIDFromPage(t *testing.T, response *http.Response) string {
	byteArr, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	response.Body = io.NopCloser(bytes.NewReader(byteArr))
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(byteArr)))
	if err != nil {
		t.Fatal(err)
	}

	field := doc.Find(`form input[name="ceremonyId"]`)
	if field.Length() != 1 {
		t.Fatalf("expecting exactly one ceremonyId input inside the form, found %d", field.Length())
	}
	ceremonyID, ok := field.Attr("value")
	if !ok || ceremonyID == "" {
		t.Fatal("the ceremonyId input carries no value")
	}
	return ceremonyID
}

func getCodeAndStateFromURL(t *testing.T, resp *http.Response) (code string, state string) {
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	code = redirectLocation.Query().Get("code")
	state = redirectLocation.Query().Get("state")

	assert.NotEmpty(t, code, "code should not be empty")
	assert.NotEmpty(t, state, "state should not be empty")

	assert.Len(t, code, 128)

	return code, state
}

// postConsent submits the consent form. consentPage is the response that rendered it, and the
// ceremony id is read out of it rather than constructed, so the submission carries what a browser
// on that page would carry (#79).
func postConsent(t *testing.T, client *http.Client, destURL string, consentPage *http.Response,
	consents []int) (resp *http.Response) {

	formData := url.Values{}
	formData.Add("ceremonyId", getCeremonyIDFromPage(t, consentPage))
	for _, consent := range consents {
		formData.Add(fmt.Sprintf("consent%d", consent), "[on]")
	}
	if len(consents) > 0 {
		formData.Add("btnSubmit", "submit")
	} else {
		formData.Add("btnCancel", "cancel")
	}

	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", destURL, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", destURL)
	request.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// createAuthenticatedHTTPClient returns a browser holding a valid level 1 session, for the tests
// that assert what an authorization ERROR looks like when it reaches the client.
//
// Since #213 the authorization endpoint no longer redirects a logged-out browser to a client's
// redirect URI on a request that failed validation: RFC 9700 4.11.2 requires that "the
// authorization server MUST always authenticate the user first ... before redirecting the user", so
// a cookieless request is sent to /auth/level1 and the error is delivered after the login. The
// tests below exist to check the error response itself, its code, description, response mode and
// state echo, which is orthogonal to who is at the browser, so each is given a session and keeps
// its assertions exactly as written (decision 6). The deferral has its own cases; it is not what
// these are for.
//
// The client and user the session was created for are discarded on purpose. A session cookie
// belongs to the browser and not to the client that minted it, so this authenticates a request for
// whichever client the caller creates for itself.
func createAuthenticatedHTTPClient(t *testing.T) *http.Client {
	httpClient, _, _, _ := createSessionWithACRLevel1(t)
	return httpClient
}

// navigateToPasswordScreen starts an auth flow and navigates to the password screen
// Returns the HTTP response for the password page
func navigateToPasswordScreen(t *testing.T, httpClient *http.Client, client *record.Client, redirectURI string) *http.Response {
	return navigateToPasswordScreenWithUILocales(t, httpClient, client, redirectURI, "")
}

// navigateToPasswordScreenWithUILocales is the same as navigateToPasswordScreen
// but appends an ui_locales query parameter (space-separated BCP 47 tags) when
// non-empty, exercising the OIDC hint preservation across the redirect chain.
func navigateToPasswordScreenWithUILocales(t *testing.T, httpClient *http.Client, client *record.Client, redirectURI, uiLocales string) *http.Response {
	requestCodeChallenge := randomCodeChallenge()
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce
	if uiLocales != "" {
		destURL += "&ui_locales=" + url.QueryEscape(uiLocales)
	}

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)
	// Note: caller is responsible for closing this response

	return resp
}

// navigateToOTPScreen starts an auth flow, authenticates with password, and navigates to OTP screen
// Returns the HTTP response for the OTP page
func navigateToOTPScreen(t *testing.T, httpClient *http.Client, client *record.Client, user *record.User,
	password string, redirectURI string) *http.Response {

	requestCodeChallenge := randomCodeChallenge()
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	// The password page is held rather than closed here: the submission reads the ceremony id out
	// of it, and a closed body cannot be read (#79).
	pwdPage := resp
	resp = authenticateWithPassword(t, httpClient, redirectLocation, pwdPage, user.Email, password)
	_ = pwdPage.Body.Close()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)
	// Note: caller is responsible for closing this response

	return resp
}

// navigateToConsentScreen completes auth flow and navigates to consent screen
// Returns the HTTP response for the consent page
func navigateToConsentScreen(t *testing.T, httpClient *http.Client, client *record.Client,
	user *record.User, password string, redirectURI string) *http.Response {

	requestCodeChallenge := randomCodeChallenge()
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destURL := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	resp, err := httpClient.Get(destURL)
	if err != nil {
		t.Fatal(err)
	}

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	// The password page is held rather than closed here: the submission reads the ceremony id out
	// of it, and a closed body cannot be read (#79).
	pwdPage := resp
	resp = authenticateWithPassword(t, httpClient, redirectLocation, pwdPage, user.Email, password)
	_ = pwdPage.Body.Close()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	_ = resp.Body.Close()
	resp = loadPage(t, httpClient, redirectLocation)
	// Note: caller is responsible for closing this response

	return resp
}
