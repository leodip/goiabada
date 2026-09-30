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
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
)

func createHttpClient(t *testing.T) *http.Client {
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

func assertRedirect(t *testing.T, response *http.Response, location string) string {
	if response.StatusCode != http.StatusFound {
		t.Fatalf("Expected status code %d, got %d", http.StatusFound, response.StatusCode)
	}

	redirectLocation, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, location, redirectLocation.Path)

	return redirectLocation.String()
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
func authenticateWithPassword(t *testing.T, client *http.Client, destUrl string,
	pwdPage *http.Response, email string, password string) *http.Response {

	formData := url.Values{
		"email":      {email},
		"password":   {password},
		"ceremonyId": {getCeremonyIdFromPage(t, pwdPage)},
	}

	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", destUrl)
	request.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// authenticateWithOtp submits the OTP form, verification or enrollment. otpPage is the response
// that rendered it, read the same way authenticateWithPassword reads its own (#79).
func authenticateWithOtp(t *testing.T, client *http.Client, destUrl string, otpPage *http.Response,
	otp string) *http.Response {

	formData := url.Values{
		"otp":        {otp},
		"ceremonyId": {getCeremonyIdFromPage(t, otpPage)},
	}

	formDataString := formData.Encode()
	requestBody := strings.NewReader(formDataString)
	request, err := http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", destUrl)
	request.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func getOtpSecretFromEnrollmentPage(t *testing.T, response *http.Response) string {
	byteArr, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	response.Body = io.NopCloser(bytes.NewReader(byteArr))
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(byteArr)))
	if err != nil {
		t.Fatal(err)
	}
	secret := doc.Find("pre.text-center")
	if secret.Length() != 1 {
		t.Fatal("expecting to find pre element with class 'text-center' but it was not found")
	}
	return secret.Text()
}

// getCeremonyIdFromPage reads the hidden ceremony id out of a rendered auth-flow page, so the
// tests post the value the server actually rendered rather than one they made up. A field rename
// on one side alone then fails here instead of passing silently (#79).
//
// The selector is scoped to inside the form, and matching anything other than exactly once is a
// failure. That is the whole point of it: a hidden input placed OUTSIDE the <form> element is not
// submitted by any browser, so every real submission would be refused, while a helper that finds
// the value anywhere on the page and posts it by hand would sail past.
//
// The body is re-buffered, as getOtpSecretFromEnrollmentPage does, so a later reader of the same
// response still sees it.
func getCeremonyIdFromPage(t *testing.T, response *http.Response) string {
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
	ceremonyId, ok := field.Attr("value")
	if !ok || ceremonyId == "" {
		t.Fatal("the ceremonyId input carries no value")
	}
	return ceremonyId
}

func getCodeAndStateFromUrl(t *testing.T, resp *http.Response) (code string, state string) {
	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	code = redirectLocation.Query().Get("code")
	state = redirectLocation.Query().Get("state")

	assert.NotEmpty(t, code, "code should not be empty")
	assert.NotEmpty(t, state, "state should not be empty")

	assert.Equal(t, 128, len(code))

	return code, state
}

// postConsent submits the consent form. consentPage is the response that rendered it, and the
// ceremony id is read out of it rather than constructed, so the submission carries what a browser
// on that page would carry (#79).
func postConsent(t *testing.T, client *http.Client, destUrl string, consentPage *http.Response,
	consents []int) (resp *http.Response) {

	formData := url.Values{}
	formData.Add("ceremonyId", getCeremonyIdFromPage(t, consentPage))
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
	request, err := http.NewRequest("POST", destUrl, requestBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Referer", destUrl)
	request.Header.Set("Origin", appConfig.AuthServer.BaseURL)

	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// createAuthenticatedHttpClient returns a browser holding a valid level 1 session, for the tests
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
func createAuthenticatedHttpClient(t *testing.T) *http.Client {
	httpClient, _, _, _ := createSessionWithAcrLevel1(t)
	return httpClient
}

// navigateToPasswordScreen starts an auth flow and navigates to the password screen
// Returns the HTTP response for the password page
func navigateToPasswordScreen(t *testing.T, httpClient *http.Client, client *models.Client, redirectUri string) *http.Response {
	return navigateToPasswordScreenWithUILocales(t, httpClient, client, redirectUri, "")
}

// navigateToPasswordScreenWithUILocales is the same as navigateToPasswordScreen
// but appends an ui_locales query parameter (space-separated BCP 47 tags) when
// non-empty, exercising the OIDC hint preservation across the redirect chain.
func navigateToPasswordScreenWithUILocales(t *testing.T, httpClient *http.Client, client *models.Client, redirectUri, uiLocales string) *http.Response {
	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce
	if uiLocales != "" {
		destUrl += "&ui_locales=" + url.QueryEscape(uiLocales)
	}

	resp, err := httpClient.Get(destUrl)
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

// navigateToOtpScreen starts an auth flow, authenticates with password, and navigates to OTP screen
// Returns the HTTP response for the OTP page
func navigateToOtpScreen(t *testing.T, httpClient *http.Client, client *models.Client, user *models.User,
	password string, redirectUri string) *http.Response {

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	resp, err := httpClient.Get(destUrl)
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
func navigateToConsentScreen(t *testing.T, httpClient *http.Client, client *models.Client,
	user *models.User, password string, redirectUri string) *http.Response {

	requestCodeChallenge := fake.LetterN(43)
	requestState := fake.LetterN(8)
	requestNonce := fake.LetterN(8)
	requestScope := "openid profile email"

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	resp, err := httpClient.Get(destUrl)
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
