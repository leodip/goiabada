package integrationtests

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	setup()
}

func TestAuthorize_ClientIdIsMissing(t *testing.T) {
	setup()
	url := lib.GetBaseUrl() + "/auth/authorize/"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "The client_id parameter is missing.", errorMsg)
}

func TestAuthorize_ClientDoesNotExist(t *testing.T) {
	setup()
	url := lib.GetBaseUrl() + "/auth/authorize/?client_id=does_not_exist"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "We couldn't find a client associated with the provided client_id.", errorMsg)
}

func TestAuthorize_ClientIsDisabled(t *testing.T) {
	setup()

	clientSetEnabled(t, "test-client-1", false)

	url := lib.GetBaseUrl() + "/auth/authorize/?client_id=test-client-1"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "The client associated with the provided client_id is not enabled.", errorMsg)

	clientSetEnabled(t, "test-client-1", true)
}

func TestAuthorize_RedirectUriIsMissing(t *testing.T) {
	setup()
	url := lib.GetBaseUrl() + "/auth/authorize/?client_id=test-client-1"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "The redirect_uri parameter is missing.", errorMsg)
}

func TestAuthorize_ClientDoesNotHaveRedirectUri(t *testing.T) {
	setup()
	url := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=http://something.com"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Invalid redirect_uri parameter. The client does not have this redirect uri configured.", errorMsg)
}

func TestAuthorize_ResponseTypeIsMissing(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: false,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, "Ensure response_type is set to 'code' as it's the only supported value.", errorDescription)
}

func TestAuthorize_ResponseTypeIsInvalid(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=invalid"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: false,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, "Ensure response_type is set to 'code' as it's the only supported value.", errorDescription)
}

func TestAuthorize_CodeChallengeMethodMissing(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: false,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, "Ensure code_challenge_method is set to 'S256' as it's the only supported value.", errorDescription)
}

func TestAuthorize_CodeChallengeMethodInvalid(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=plain"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: false,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, "Ensure code_challenge_method is set to 'S256' as it's the only supported value.", errorDescription)
}

func TestAuthorize_CodeChallengeMissing(t *testing.T) {
	setup()
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: false,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, "The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.", errorDescription)
}

func TestAuthorize_CodeChallengeInvalid(t *testing.T) {
	setup()

	testCases := []struct {
		codeChallenge string
	}{
		// less than 43
		{codeChallenge: "abcabc"},

		// more than 128
		{codeChallenge: "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca"},
	}

	for _, testCase := range testCases {

		destUrl := lib.GetBaseUrl() +
			"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
			"&code_challenge_method=S256&code_challenge=" + testCase.codeChallenge

		client := createHttpClient(&createHttpClientInput{
			T:               t,
			FollowRedirects: false,
			IgnoreTLSErrors: true,
		})

		resp, err := client.Get(destUrl)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusFound, resp.StatusCode)

		redirectLocation, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		errorCode := redirectLocation.Query().Get("error")
		errorDescription := redirectLocation.Query().Get("error_description")

		assert.Equal(t, "invalid_request", errorCode)
		assert.Equal(t, "The code_challenge parameter is either missing or incorrect. It should be 43 to 128 characters long.", errorDescription)
	}
}

func TestAuthorize_InvalidResponseMode(t *testing.T) {
	setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=invalid"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: false,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, "Please use 'query,' 'fragment,' or 'form_post' as the response_mode value.", errorDescription)
}

func TestAuthorize_AccetableResponseModes(t *testing.T) {
	setup()

	testCases := []struct {
		responseMode string
	}{

		{responseMode: "query"},
		{responseMode: "fragment"},
		{responseMode: "form_post"},
	}

	for _, testCase := range testCases {

		codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
		destUrl := lib.GetBaseUrl() +
			"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
			"&code_challenge_method=S256&code_challenge=" + codeChallenge +
			"&response_mode=" + testCase.responseMode

		client := createHttpClient(&createHttpClientInput{
			T:               t,
			FollowRedirects: false,
			IgnoreTLSErrors: true,
		})

		resp, err := client.Get(destUrl)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusFound, resp.StatusCode)

		redirectLocation, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, "https://goiabada.local:8080/auth/pwd", redirectLocation.String())
	}
}

func TestAuthorize_InvalidScope(t *testing.T) {

	testCases := []struct {
		scope            string
		errorCode        string
		errorDescription string
	}{
		{
			scope:            "a:b:c",
			errorCode:        "invalid_scope",
			errorDescription: "Invalid scope format: 'a:b:c'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.",
		},
		{
			scope:            "aaa",
			errorCode:        "invalid_scope",
			errorDescription: "Invalid scope format: 'aaa'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.",
		},
		{
			scope:            "res:perm",
			errorCode:        "invalid_scope",
			errorDescription: "Invalid scope: 'res:perm'. Could not find a resource with identifier 'res'.",
		},
		{
			scope:            "backend-svcA:perm",
			errorCode:        "invalid_scope",
			errorDescription: "Scope 'backend-svcA:perm' is not recognized. The resource identified by 'backend-svcA' doesn't grant the 'perm' permission.",
		},
	}

	setup()

	for _, testCase := range testCases {

		codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
		destUrl := lib.GetBaseUrl() +
			"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
			"&code_challenge_method=S256&code_challenge=" + codeChallenge +
			"&response_mode=query&scope=" + testCase.scope

		client := createHttpClient(&createHttpClientInput{
			T:               t,
			FollowRedirects: false,
			IgnoreTLSErrors: true,
		})

		resp, err := client.Get(destUrl)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusFound, resp.StatusCode)

		redirectLocation, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		errorCode := redirectLocation.Query().Get("error")
		errorDescription := redirectLocation.Query().Get("error_description")

		assert.Equal(t, testCase.errorCode, errorCode)
		assert.Equal(t, testCase.errorDescription, errorDescription)
	}
}

func TestAuthorize_PermissionNotGrantedToUser(t *testing.T) {
	setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=backend-svcA:create-product"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, client, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p.text-error").Text()
	assert.Equal(t, "Permission to access scope 'backend-svcA:create-product' is not granted to the user.", errorMsg)
}

func TestAuthorize_OneLogin_Pwd_WithFullConsent(t *testing.T) {
	setup()

	// make sure otp is disabled for the user
	setOTPEnabled(t, "mauro@outlook.com", false)

	// make sure there's no prior user consent
	clientSetConsentRequired(t, "test-client-1", true)
	deleteAllUserConsents(t)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, client, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	// consent page
	csrf = getCsrfValue(t, resp)

	// disable follow redirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp = postConsent(t, client, []int{0, 1, 2, 3}, csrf)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	code, err := database.GetCode(codeVal, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, "1", code.AcrLevel)
	assert.Equal(t, "pwd", code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada.local:8090/callback.html", code.RedirectUri)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_OneLogin_Pwd_CancelConsent(t *testing.T) {
	setup()

	// make sure otp is disabled for the user
	setOTPEnabled(t, "mauro@outlook.com", false)

	// make sure there's no prior user consent
	clientSetConsentRequired(t, "test-client-1", true)
	deleteAllUserConsents(t)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, client, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	// consent page
	csrf = getCsrfValue(t, resp)

	// disable follow redirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp = postConsent(t, client, []int{}, csrf)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, "access_denied", errorCode)
	assert.Equal(t, "The user did not provide consent", errorDescription)
	assert.Equal(t, "a1b2c3", stateVal)
}

func TestAuthorize_OneLogin_Pwd_WithPartialConsent(t *testing.T) {
	setup()

	// make sure otp is disabled for the user
	setOTPEnabled(t, "mauro@outlook.com", false)

	// make sure there's no prior user consent
	clientSetConsentRequired(t, "test-client-1", true)
	deleteAllUserConsents(t)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, client, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	// consent page
	csrf = getCsrfValue(t, resp)

	// disable follow redirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// consent only to 2 out of 4 scopes requested
	resp = postConsent(t, client, []int{0, 3}, csrf)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	code, err := database.GetCode(codeVal, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid backend-svcA:read-product", code.Scope) // partial consent
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, "1", code.AcrLevel)
	assert.Equal(t, "pwd", code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada.local:8090/callback.html", code.RedirectUri)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_OneLogin_Pwd_NoConsentRequired(t *testing.T) {
	setup()

	// make sure otp is disabled for the user
	setOTPEnabled(t, "mauro@outlook.com", false)

	clientSetConsentRequired(t, "test-client-1", false)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// disable follow redirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, client, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "/auth/consent", redirectLocation.Path)

	resp = loadConsentPage(t, client)
	defer resp.Body.Close()

	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	code, err := database.GetCode(codeVal, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, "1", code.AcrLevel)
	assert.Equal(t, "pwd", code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada.local:8090/callback.html", code.RedirectUri)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_OneLogin_Pwd_Otp_WithFullConsent(t *testing.T) {
	setup()

	// make sure otp is enabled for the user
	setOTPEnabled(t, "mauro@outlook.com", true)

	// make sure there's no prior user consent
	clientSetConsentRequired(t, "test-client-1", true)
	deleteAllUserConsents(t)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, client, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	// otp page
	csrf = getCsrfValue(t, resp)

	otp, err := totp.GenerateCode("ILMGDC577J4A4HTR5POU4BU5H5W7VYM2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, client, otp, csrf)

	// consent page
	csrf = getCsrfValue(t, resp)

	// disable follow redirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp = postConsent(t, client, []int{0, 1, 2, 3}, csrf)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	code, err := database.GetCode(codeVal, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, "2", code.AcrLevel)
	assert.Equal(t, "pwd otp", code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada.local:8090/callback.html", code.RedirectUri)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_TwoLogins_Pwd_NoConsentRequired(t *testing.T) {
	setup()

	// make sure otp is disabled for the user
	setOTPEnabled(t, "mauro@outlook.com", false)

	clientSetConsentRequired(t, "test-client-1", false)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// disable follow redirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, client, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "/auth/consent", redirectLocation.Path)

	resp = loadConsentPage(t, client)
	defer resp.Body.Close()

	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	code, err := database.GetCode(codeVal, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, "1", code.AcrLevel)
	assert.Equal(t, "pwd", code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada.local:8090/callback.html", code.RedirectUri)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)

	// second login (won't need to authenticate with pwd again)

	resp, err = client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "/auth/consent", redirectLocation.Path)

	resp = loadConsentPage(t, client)
	defer resp.Body.Close()

	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal = redirectLocation.Query().Get("code")
	stateVal = redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	code, err = database.GetCode(codeVal, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, "1", code.AcrLevel)
	assert.Equal(t, "pwd", code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada.local:8090/callback.html", code.RedirectUri)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_OneLogin_Pwd_WithPreviousConsentGiven(t *testing.T) {
	setup()

	// make sure otp is disabled for the user
	setOTPEnabled(t, "mauro@outlook.com", false)

	clientSetConsentRequired(t, "test-client-1", true)
	grantConsent(t, "test-client-1", "mauro@outlook.com", "openid profile email backend-svcA:read-product")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// disable follow redirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, client, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "/auth/consent", redirectLocation.Path)

	resp = loadConsentPage(t, client)
	defer resp.Body.Close()

	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	code, err := database.GetCode(codeVal, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, "1", code.AcrLevel)
	assert.Equal(t, "pwd", code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada.local:8090/callback.html", code.RedirectUri)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_TwoLogins_Pwd_WithAcrLevel1Downgrade(t *testing.T) {
	setup()

	// make sure otp is disabled for the user
	setOTPEnabled(t, "mauro@outlook.com", false)

	clientSetConsentRequired(t, "test-client-1", false)

	originalMaxAge := settingsGetAcrLevel1MaxAgeInSeconds(t)
	settingsSetAcrLevel1MaxAgeInSeconds(t, 1)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// disable follow redirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, client, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "/auth/consent", redirectLocation.Path)

	resp = loadConsentPage(t, client)
	defer resp.Body.Close()

	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	code, err := database.GetCode(codeVal, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, "1", code.AcrLevel)
	assert.Equal(t, "pwd", code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada.local:8090/callback.html", code.RedirectUri)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)

	// wait for acr downgrade to happen
	time.Sleep(2 * time.Second)

	// second login (won't need to authenticate with pwd again)

	resp, err = client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "/auth/consent", redirectLocation.Path)

	resp = loadConsentPage(t, client)
	defer resp.Body.Close()

	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal = redirectLocation.Query().Get("code")
	stateVal = redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	code, err = database.GetCode(codeVal, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, "0", code.AcrLevel) // acr downgrade
	assert.Equal(t, "pwd", code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada.local:8090/callback.html", code.RedirectUri)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)

	settingsSetAcrLevel1MaxAgeInSeconds(t, originalMaxAge)
}

func TestAuthorize_TwoLogins_Pwd_WithAcrLevel2Downgrade(t *testing.T) {
	setup()

	// make sure otp is enabled for the user
	setOTPEnabled(t, "mauro@outlook.com", true)

	clientSetConsentRequired(t, "test-client-1", false)

	originalMaxAge := settingsGetAcrLevel2MaxAgeInSeconds(t)
	settingsSetAcrLevel2MaxAgeInSeconds(t, 1)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada.local:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, client, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	// otp page
	csrf = getCsrfValue(t, resp)

	otp, err := totp.GenerateCode("ILMGDC577J4A4HTR5POU4BU5H5W7VYM2", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// disable follow redirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp = authenticateWithOtp(t, client, otp, csrf)
	defer resp.Body.Close()

	resp = loadConsentPage(t, client)
	defer resp.Body.Close()

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal := redirectLocation.Query().Get("code")
	stateVal := redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	code, err := database.GetCode(codeVal, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, "2", code.AcrLevel)
	assert.Equal(t, "pwd otp", code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada.local:8090/callback.html", code.RedirectUri)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)

	// wait for acr downgrade to happen
	time.Sleep(2 * time.Second)

	// second login (won't need to authenticate with pwd again)

	resp, err = client.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "/auth/consent", redirectLocation.Path)

	resp = loadConsentPage(t, client)
	defer resp.Body.Close()

	redirectLocation, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	codeVal = redirectLocation.Query().Get("code")
	stateVal = redirectLocation.Query().Get("state")

	assert.Equal(t, 128, len(codeVal))
	assert.Equal(t, "a1b2c3", stateVal)

	code, err = database.GetCode(codeVal, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, "0", code.AcrLevel) // acr downgrade
	assert.Equal(t, "pwd otp", code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada.local:8090/callback.html", code.RedirectUri)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)

	settingsSetAcrLevel2MaxAgeInSeconds(t, originalMaxAge)
}
