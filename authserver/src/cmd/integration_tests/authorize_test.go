package integrationtests

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/enums"
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

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
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

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
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

	url := lib.GetBaseUrl() + "/auth/authorize/?client_id=test-client-3"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
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
}

func TestAuthorize_RedirectURIIsMissing(t *testing.T) {
	setup()
	url := lib.GetBaseUrl() + "/auth/authorize/?client_id=test-client-1"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
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

func TestAuthorize_ClientDoesNotHaveRedirectURI(t *testing.T) {
	setup()
	url := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=http://something.com"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
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
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
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
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=invalid"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
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
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
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
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=plain"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
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
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
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
			"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
			"&code_challenge_method=S256&code_challenge=" + testCase.codeChallenge

		httpClient := createHttpClient(&createHttpClientInput{
			T: t,
		})

		resp, err := httpClient.Get(destUrl)
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
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=invalid"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
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
			"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
			"&code_challenge_method=S256&code_challenge=" + codeChallenge + "&scope=openid%20email%20profile" +
			"&response_mode=" + testCase.responseMode

		httpClient := createHttpClient(&createHttpClientInput{
			T: t,
		})

		resp, err := httpClient.Get(destUrl)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusFound, resp.StatusCode)

		redirectLocation, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, lib.GetBaseUrl()+"/auth/pwd", redirectLocation.String())
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
			"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
			"&code_challenge_method=S256&code_challenge=" + codeChallenge +
			"&response_mode=query&scope=" + testCase.scope

		httpClient := createHttpClient(&createHttpClientInput{
			T: t,
		})

		resp, err := httpClient.Get(destUrl)
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
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&state=a1b2c3&response_mode=query&scope=openid%20backend-svcA:create-product%20backend-svcA:read-product" +
		"&acr_values=" + enums.AcrLevel1.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")

	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	// scope backend-svcA:create-product was removed because user didn't have access to it
	assert.Equal(t, "openid backend-svcA:read-product", code.Scope)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_OneLogin_Pwd_WithFullConsent(t *testing.T) {
	setup()

	// make sure there's no prior user consent
	deleteAllUserConsents(t)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "viviane@gmail.com", "asd123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	// consent page
	csrf = getCsrfValue(t, resp)

	resp = postConsent(t, httpClient, []int{0, 1, 2, 3}, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, enums.AcrLevel2.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "viviane@gmail.com", code.User.Email)
}

func TestAuthorize_OneLogin_Pwd_CancelConsent(t *testing.T) {
	setup()

	deleteAllUserConsents(t)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "viviane@gmail.com", "asd123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	// consent page
	csrf = getCsrfValue(t, resp)

	resp = postConsent(t, httpClient, []int{}, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")

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

	// make sure there's no prior user consent
	deleteAllUserConsents(t)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	// consent page
	csrf = getCsrfValue(t, resp)

	// consent only to 2 out of 4 scopes requested
	resp = postConsent(t, httpClient, []int{0, 3}, csrf)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid backend-svcA:read-product", code.Scope) // partial consent
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_OneLogin_Pwd_NoConsentRequired(t *testing.T) {
	setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_OneLogin_Pwd_Otp_WithFullConsent(t *testing.T) {
	setup()

	// make sure there's no prior user consent
	deleteAllUserConsents(t)

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/otp")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/otp")
	defer resp.Body.Close()

	// otp page
	csrf = getCsrfValue(t, resp)

	otp, err := totp.GenerateCode("ILMGDC577J4A4HTR5POU4BU5H5W7VYM2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, otp, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	// consent page
	csrf = getCsrfValue(t, resp)

	resp = postConsent(t, httpClient, []int{0, 1, 2, 3}, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, enums.AcrLevel2.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_TwoLogins_Pwd_NoConsentRequired(t *testing.T) {
	setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)

	// second login (won't need to authenticate with pwd again)

	resp, err = httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal = getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err = lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err = database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_OneLogin_Pwd_WithPreviousConsentGiven(t *testing.T) {
	setup()

	grantConsent(t, "test-client-1", "mauro@outlook.com", "openid profile email backend-svcA:read-product")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_TwoLogins_Pwd_WithMaxAge(t *testing.T) {
	setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-1&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email%20backend-svcA%3Aread-product&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	// pwd page
	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)

	// second login (won't need to authenticate with pwd again)

	// the max age of 1s will force re-authentication
	destUrl += "&max_age=1"
	time.Sleep(2 * time.Second)

	resp, err = httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	// pwd page
	csrf = getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal = getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err = lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err = database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "openid profile email backend-svcA:read-product", code.Scope)
	assert.Equal(t, "a1b2c3", code.State)
	assert.Equal(t, "m9n8b7", code.Nonce)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-1", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_NoPreviousSession_TargetAcrLevel1_OTPDisabled(t *testing.T) {
	setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "viviane@gmail.com", "asd123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "viviane@gmail.com", code.User.Email)
}

func TestAuthorize_NoPreviousSession_TargetAcrLevel2_OTPDisabled(t *testing.T) {
	setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel2.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "viviane@gmail.com", "asd123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel2.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "viviane@gmail.com", code.User.Email)
}

func TestAuthorize_NoPreviousSession_TargetAcrLevel3_OTPDisabled(t *testing.T) {
	setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel3.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	user := getRandomUserWithOtpState(t, false)

	resp = authenticateWithPassword(t, httpClient, user.Email, "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/otp")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/otp")
	defer resp.Body.Close()

	// otp page
	csrf = getCsrfValue(t, resp)
	otpSecret := getOtpSecret(t, resp)

	otp, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	resp = authenticateWithOtp(t, httpClient, otp, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, user.Email, code.User.Email)

	user.OTPEnabled = false
	user.OTPSecret = ""
	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthorize_NoPreviousSession_TargetAcrLevel1_OTPEnabled(t *testing.T) {
	setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_NoPreviousSession_TargetAcrLevel2_OTPEnabled(t *testing.T) {
	setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel2.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/otp")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/otp")
	defer resp.Body.Close()

	// otp page
	csrf = getCsrfValue(t, resp)
	otpSecret, err := totp.GenerateCode("ILMGDC577J4A4HTR5POU4BU5H5W7VYM2", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	resp = authenticateWithOtp(t, httpClient, otpSecret, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel2.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_NoPreviousSession_TargetAcrLevel3_OTPEnabled(t *testing.T) {
	setup()

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel3.String()

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/pwd")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/pwd")
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, "mauro@outlook.com", "abc123", csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/otp")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/otp")
	defer resp.Body.Close()

	// otp page
	csrf = getCsrfValue(t, resp)
	otpSecret, err := totp.GenerateCode("ILMGDC577J4A4HTR5POU4BU5H5W7VYM2", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	resp = authenticateWithOtp(t, httpClient, otpSecret, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel1Session_TargetAcrLevel1_OTPDisabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel1(t, "viviane@gmail.com", "asd123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "viviane@gmail.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel1Session_TargetAcrLevel2_OTPDisabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel1(t, "viviane@gmail.com", "asd123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel2.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel2.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "viviane@gmail.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel1Session_TargetAcrLevel3_OTPDisabled(t *testing.T) {
	setup()

	user := getRandomUserWithOtpState(t, false)

	httpClient := loginUserWithAcrLevel1(t, user.Email, "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel3.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/otp")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/otp")
	defer resp.Body.Close()

	// otp page
	csrf := getCsrfValue(t, resp)
	otpSecret := getOtpSecret(t, resp)

	otp, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	resp = authenticateWithOtp(t, httpClient, otp, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, user.Email, code.User.Email)

	user.OTPEnabled = false
	user.OTPSecret = ""
	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthorize_PreviousAcrLevel1Session_TargetAcrLevel1_OTPEnabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel1(t, "mauro@outlook.com", "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel1Session_TargetAcrLevel2_OTPEnabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel1(t, "mauro@outlook.com", "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel2.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/otp")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/otp")
	defer resp.Body.Close()

	// otp page
	csrf := getCsrfValue(t, resp)

	otp, err := totp.GenerateCode("ILMGDC577J4A4HTR5POU4BU5H5W7VYM2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, otp, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel2.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel1Session_TargetAcrLevel3_OTPEnabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel1(t, "mauro@outlook.com", "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel3.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/otp")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/otp")
	defer resp.Body.Close()

	// otp page
	csrf := getCsrfValue(t, resp)

	otp, err := totp.GenerateCode("ILMGDC577J4A4HTR5POU4BU5H5W7VYM2", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	resp = authenticateWithOtp(t, httpClient, otp, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel2Session_TargetAcrLevel1_OTPDisabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel2(t, "viviane@gmail.com", "asd123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel2.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "viviane@gmail.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel2Session_TargetAcrLevel2_OTPDisabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel2(t, "viviane@gmail.com", "asd123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel2.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel2.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "viviane@gmail.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel2Session_TargetAcrLevel3_OTPDisabled(t *testing.T) {
	setup()

	user := getRandomUserWithOtpState(t, false)

	httpClient := loginUserWithAcrLevel2(t, user.Email, "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel3.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/otp")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/otp")
	defer resp.Body.Close()

	// otp page
	csrf := getCsrfValue(t, resp)
	otpSecret := getOtpSecret(t, resp)

	otp, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	resp = authenticateWithOtp(t, httpClient, otp, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, user.Email, code.User.Email)
}

func TestAuthorize_PreviousAcrLevel2Session_TargetAcrLevel1_OTPEnabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel2(t, "mauro@outlook.com", "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel2.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel2Session_TargetAcrLevel2_OTPEnabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel2(t, "mauro@outlook.com", "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel2.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel2.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel2Session_TargetAcrLevel3_OTPEnabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel2(t, "mauro@outlook.com", "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel3.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/otp")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/otp")
	defer resp.Body.Close()

	// otp page
	csrf := getCsrfValue(t, resp)
	otp, err := totp.GenerateCode("ILMGDC577J4A4HTR5POU4BU5H5W7VYM2", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	resp = authenticateWithOtp(t, httpClient, otp, csrf)
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel3Session_TargetAcrLevel1_OTPDisabled(t *testing.T) {
	setup()

	user := getRandomUserWithOtpState(t, false)

	httpClient := loginUserWithAcrLevel3(t, user.Email, "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, user.Email, code.User.Email)
}

func TestAuthorize_PreviousAcrLevel3Session_TargetAcrLevel2_OTPDisabled(t *testing.T) {
	setup()

	user := getRandomUserWithOtpState(t, false)

	httpClient := loginUserWithAcrLevel3(t, user.Email, "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel2.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, user.Email, code.User.Email)
}

func TestAuthorize_PreviousAcrLevel3Session_TargetAcrLevel3_OTPDisabled(t *testing.T) {
	setup()

	user := getRandomUserWithOtpState(t, false)

	httpClient := loginUserWithAcrLevel3(t, user.Email, "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel3.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, user.Email, code.User.Email)
}

func TestAuthorize_PreviousAcrLevel3Session_TargetAcrLevel1_OTPEnabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel3(t, "mauro@outlook.com", "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel3Session_TargetAcrLevel2_OTPEnabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel3(t, "mauro@outlook.com", "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel2.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}

func TestAuthorize_PreviousAcrLevel3Session_TargetAcrLevel3_OTPEnabled(t *testing.T) {
	setup()

	httpClient := loginUserWithAcrLevel3(t, "mauro@outlook.com", "abc123")

	codeChallenge := "bQCdz4Hkhb3ctpajAwCCN899mNNfQGmRvMwruYT1Y9Y"
	destUrl := lib.GetBaseUrl() +
		"/auth/authorize/?client_id=test-client-2&redirect_uri=https://goiabada-test-client:8090/callback.html&response_type=code" +
		"&code_challenge_method=S256&code_challenge=" + codeChallenge +
		"&response_mode=query&scope=openid%20profile%20email&state=a1b2c3&nonce=m9n8b7" +
		"&acr_values=" + enums.AcrLevel3.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/consent")
	resp = getPage(t, httpClient, lib.GetBaseUrl()+"/auth/consent")
	defer resp.Body.Close()

	assertRedirect(t, resp, "/callback.html")
	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)

	assert.Equal(t, "a1b2c3", stateVal)

	codeHash, err := lib.HashString(codeVal)
	if err != nil {
		t.Fatal(err)
	}
	code, err := database.GetCodeByCodeHash(codeHash, false)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "openid profile email", code.Scope)
	assert.Equal(t, enums.AcrLevel3.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String()+" "+enums.AuthMethodOTP.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
	assert.Equal(t, "test-client-2", code.Client.ClientIdentifier)
	assert.Equal(t, "https://goiabada-test-client:8090/callback.html", code.RedirectURI)
	assert.Equal(t, "mauro@outlook.com", code.User.Email)
}
