package integrationtests

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestAuthorize_ValidateClientAndRedirectURI_ClientIdIsMissing(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/"

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "The client_id parameter is missing.", errorMsg)
}

func TestAuthorize_ValidateClientAndRedirectURI_ClientDoesNotExist(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=does_not_exist"

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Invalid client_id parameter. The client does not exist.", errorMsg)
}

func TestAuthorize_ValidateClientAndRedirectURI_ClientIsDisabled(t *testing.T) {
	client := &models.Client{
		ClientIdentifier: "test-client-" + gofakeit.LetterN(8),
		Enabled:          false,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Invalid client_id parameter. The client is disabled.", errorMsg)
}

func TestAuthorize_ValidateClientAndRedirectURI_ClientDoesNotSupportTheAuthorizationCodeFlow(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: false,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Invalid client_id parameter. The client does not support the authorization code flow.", errorMsg)
}

func TestAuthorize_ValidateClientAndRedirectURI_RedirectURIIsMissing(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "The redirect_uri parameter is missing.", errorMsg)
}

func TestAuthorize_ValidateClientAndRedirectURI_ClientDoesNotHaveRedirectURI(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier + "&redirect_uri=" + gofakeit.URL()

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Invalid redirect_uri parameter. The client does not have this redirect URI registered.", errorMsg)
}

func TestAuthorize_ValidateRequest_ResponseTypeIsMissing(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + redirectUri.URI

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

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

func TestAuthorize_ValidateRequest_ResponseTypeIsInvalid(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + redirectUri.URI + "&response_type=invalid"

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

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

func TestAuthorize_ValidateRequest_CodeChallengeMethodIsMissing(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + redirectUri.URI + "&response_type=code"

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, "PKCE is required. Ensure code_challenge_method is set to 'S256'.", errorDescription)
}

func TestAuthorize_ValidateRequest_CodeChallengeMethodIsInvalid(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + redirectUri.URI + "&response_type=code" + "&code_challenge_method=invalid"

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, "PKCE is required. Ensure code_challenge_method is set to 'S256'.", errorDescription)
}

func TestAuthorize_ValidateRequest_CodeChallengeIsMissing(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + redirectUri.URI + "&response_type=code" + "&code_challenge_method=S256"

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

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

func TestAuthorize_ValidateRequest_CodeChallengeInvalid(t *testing.T) {
	testCases := []struct {
		codeChallenge string
	}{
		// less than 43
		{codeChallenge: gofakeit.LetterN(42)},

		// more than 128
		{codeChallenge: gofakeit.LetterN(129)},
	}

	for _, testCase := range testCases {
		client := &models.Client{
			ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
		}

		err := database.CreateClient(nil, client)
		if err != nil {
			t.Fatal(err)
		}

		redirectUri := &models.RedirectURI{
			ClientId: client.Id,
			URI:      gofakeit.URL(),
		}

		err = database.CreateRedirectURI(nil, redirectUri)
		if err != nil {
			t.Fatal(err)
		}

		destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
			"&redirect_uri=" + redirectUri.URI + "&response_type=code" + "&code_challenge_method=S256" +
			"&code_challenge=" + testCase.codeChallenge

		httpClient := createHttpClient(t)

		resp, err := httpClient.Get(destUrl)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()

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

func TestAuthorize_ValidateRequest_InvalidResponseMode(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + redirectUri.URI +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&response_mode=invalid"

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_request", errorCode)
	assert.Equal(t, "Invalid response_mode parameter. Supported values are: query, fragment, form_post.", errorDescription)
}

func TestAuthorize_ValidateRequest_QueryResponseMode(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + redirectUri.URI +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&response_mode=query" +
		"&scope=invalid_scope" // to prevent full authorize execution

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_scope", errorCode)
	assert.Contains(t, errorDescription, "Invalid scope format")
}

func TestAuthorize_ValidateRequest_FragmentResponseMode(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + redirectUri.URI +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&response_mode=fragment" +
		"&scope=invalid_scope" // to prevent full authorize execution

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	fragment, _ := url.ParseQuery(redirectLocation.Fragment)
	errorCode := fragment.Get("error")
	errorDescription := fragment.Get("error_description")

	assert.Equal(t, "invalid_scope", errorCode)
	assert.Contains(t, errorDescription, "Invalid scope format")
}

func TestAuthorize_ValidateRequest_FormPostResponseMode(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + redirectUri.URI +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&response_mode=form_post" +
		"&scope=invalid_scope" // to prevent full authorize execution

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	formAction, exists := doc.Find("form").Attr("action")
	assert.True(t, exists, "Form action should exist")
	assert.Equal(t, redirectUri.URI, formAction, "Form action should match redirect URI")

	errorValue := doc.Find("input[name='error']").AttrOr("value", "")
	assert.Equal(t, "invalid_scope", errorValue, "Error value should be 'invalid_scope'")

	errorDescription := doc.Find("input[name='error_description']").AttrOr("value", "")
	assert.Contains(t, errorDescription, "Invalid scope format", "Error description should contain 'Invalid scope format'")
}

func TestAuthorize_ValidateScopes_ScopeIsMissing(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + redirectUri.URI +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43)

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_scope", errorCode)
	assert.Contains(t, errorDescription, "The 'scope' parameter is missing")
}

func TestAuthorize_ValidateScopes_UserInfoShouldNotBeIncluded(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	userInfoScope := fmt.Sprintf("%v:%v", constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)

	baseUrl := config.GetAuthServer().BaseURL + "/auth/authorize/"
	params := url.Values{}
	params.Add("client_id", client.ClientIdentifier)
	params.Add("redirect_uri", redirectUri.URI)
	params.Add("response_type", "code")
	params.Add("code_challenge_method", "S256")
	params.Add("code_challenge", gofakeit.LetterN(43))
	params.Add("scope", "openid profile "+userInfoScope)

	destUrl := baseUrl + "?" + params.Encode()

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_scope", errorCode)
	assert.Contains(t, errorDescription, "The 'authserver:userinfo' scope is automatically included in the access token")
}

func TestAuthorize_ValidateScopes_InvalidScope(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name  string
		scope string
	}{
		{
			name:  "Invalid single scope",
			scope: "my_scope",
		},
		{
			name:  "Invalid complex scope",
			scope: "my_resource:my_scope:something",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
				"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
				"&response_type=code" +
				"&code_challenge_method=S256" +
				"&code_challenge=" + gofakeit.LetterN(43) +
				"&scope=" + url.QueryEscape(tc.scope)

			httpClient := createHttpClient(t)

			resp, err := httpClient.Get(destUrl)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, http.StatusFound, resp.StatusCode)

			redirectLocation, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}

			errorCode := redirectLocation.Query().Get("error")
			errorDescription := redirectLocation.Query().Get("error_description")

			assert.Equal(t, "invalid_scope", errorCode)
			assert.Contains(t, errorDescription, "Invalid scope format")
		})
	}
}

func TestAuthorize_ValidateScopes_ResourceDoesNotExist(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	nonExistentResource := "non_existent_resource"
	scope := fmt.Sprintf("%s:read", nonExistentResource)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape(scope)

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_scope", errorCode)
	assert.Contains(t, errorDescription, fmt.Sprintf("Invalid scope: '%s:read'. Could not find a resource with identifier '%s'", nonExistentResource, nonExistentResource))
}

func TestAuthorize_ValidateScopes_ResourceDoesNotHavePermissionAssociated(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	resource := &models.Resource{
		ResourceIdentifier: "test-resource-" + gofakeit.LetterN(8),
		Description:        "Test Resource",
	}

	err = database.CreateResource(nil, resource)
	if err != nil {
		t.Fatal(err)
	}

	nonExistentPermission := "non_existent_permission"
	scope := fmt.Sprintf("%s:%s", resource.ResourceIdentifier, nonExistentPermission)

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + gofakeit.LetterN(43) +
		"&scope=" + url.QueryEscape(scope)

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	errorCode := redirectLocation.Query().Get("error")
	errorDescription := redirectLocation.Query().Get("error_description")

	assert.Equal(t, "invalid_scope", errorCode)
	assert.Contains(t, errorDescription, fmt.Sprintf("Scope '%s:%s' is invalid. The resource identified by '%s' does not have a permission with identifier '%s'", resource.ResourceIdentifier, nonExistentPermission, resource.ResourceIdentifier, nonExistentPermission))
}

func TestAuthorize_NoExistingSession_AcrLevel1_Pwd_ConsentIsNotRequired(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
}

func TestAuthorize_NoExistingSession_AcrLevel2Optional_Pwd_OtpDisabled_ConsentIsNotRequired(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)
}

func TestAuthorize_NoExistingSession_AcrLevel2Optional_Pwd_OtpEnabled_ConsentIsNotRequired(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpDisabled_ConsentIsNotRequired(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Mandatory,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	otpSecret := getOtpSecretFromEnrollmentPage(t, resp)
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpEnabled_ConsentIsNotRequired(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Mandatory,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)
}

func TestAuthorize_NoExistingSession_AcrLevel1_Pwd_ConsentIsRequired_ConsentIsFullyGranted(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 1, 2, 3, 4}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, consent)
	assert.Equal(t, user.Id, consent.UserId)
	assert.Equal(t, client.Id, consent.ClientId)
	assertWithinLastXSeconds(t, consent.GrantedAt.Time, 3)
	assert.Equal(t, requestScope, consent.Scope)
}

func TestAuthorize_NoExistingSession_AcrLevel1_Pwd_ConsentIsRequired_ConsentIsPartiallyGranted(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 2, 4}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	// partially granted consent
	expectedScope := "openid email " + resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, expectedScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, consent)
	assert.Equal(t, user.Id, consent.UserId)
	assert.Equal(t, client.Id, consent.ClientId)
	assertWithinLastXSeconds(t, consent.GrantedAt.Time, 3)
	assert.Equal(t, expectedScope, consent.Scope)
}

func TestAuthorize_NoExistingSession_AcrLevel2Optional_Pwd_OtpDisabled_ConsentIsRequired_ConsentIsFullyGranted(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 1, 2, 3, 4}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, consent)
	assert.Equal(t, user.Id, consent.UserId)
	assert.Equal(t, client.Id, consent.ClientId)
	assertWithinLastXSeconds(t, consent.GrantedAt.Time, 3)
	assert.Equal(t, requestScope, consent.Scope)
}

func TestAuthorize_NoExistingSession_AcrLevel2Optional_Pwd_OtpDisabled_ConsentIsRequired_ConsentIsPartiallyGranted(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	// Partially grant consent (only for openid, email, and one resource permission)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 2, 4}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	// Expected scope after partial consent
	expectedScope := "openid email " + resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, expectedScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, consent)
	assert.Equal(t, user.Id, consent.UserId)
	assert.Equal(t, client.Id, consent.ClientId)
	assertWithinLastXSeconds(t, consent.GrantedAt.Time, 3)
	assert.Equal(t, expectedScope, consent.Scope)
}

func TestAuthorize_NoExistingSession_AcrLevel2Optional_Pwd_OtpEnabled_ConsentIsRequired_ConsentIsFullyGranted(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 1, 2, 3, 4}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, consent)
	assert.Equal(t, user.Id, consent.UserId)
	assert.Equal(t, client.Id, consent.ClientId)
	assertWithinLastXSeconds(t, consent.GrantedAt.Time, 3)
	assert.Equal(t, requestScope, consent.Scope)
}

func TestAuthorize_NoExistingSession_AcrLevel2Optional_Pwd_OtpEnabled_ConsentIsRequired_ConsentIsPartiallyGranted(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	// Simulate partial consent by only consenting to some scopes
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 2, 4}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	// Expected scope after partial consent
	expectedScope := "openid email " + resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, expectedScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, consent)
	assert.Equal(t, user.Id, consent.UserId)
	assert.Equal(t, client.Id, consent.ClientId)
	assertWithinLastXSeconds(t, consent.GrantedAt.Time, 3)
	assert.Equal(t, expectedScope, consent.Scope)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpDisabled_ConsentIsRequired_ConsentIsFullyGranted(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Mandatory,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	otpSecret := getOtpSecretFromEnrollmentPage(t, resp)
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 1, 2, 3, 4}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, consent)
	assert.Equal(t, user.Id, consent.UserId)
	assert.Equal(t, client.Id, consent.ClientId)
	assertWithinLastXSeconds(t, consent.GrantedAt.Time, 3)
	assert.Equal(t, requestScope, consent.Scope)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpDisabled_ConsentIsRequired_ConsentIsPartiallyGranted(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Mandatory,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	otpSecret := getOtpSecretFromEnrollmentPage(t, resp)
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)

	// Partially grant consent (only for openid, email, and the second resource/permission)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 2, 4}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	// Expected scope after partial consent
	expectedScope := "openid email " + resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, expectedScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, consent)
	assert.Equal(t, user.Id, consent.UserId)
	assert.Equal(t, client.Id, consent.ClientId)
	assertWithinLastXSeconds(t, consent.GrantedAt.Time, 3)
	assert.Equal(t, expectedScope, consent.Scope)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpEnabled_ConsentIsRequired_ConsentIsFullyGranted(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Mandatory,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 1, 2, 3, 4}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, consent)
	assert.Equal(t, user.Id, consent.UserId)
	assert.Equal(t, client.Id, consent.ClientId)
	assertWithinLastXSeconds(t, consent.GrantedAt.Time, 3)
	assert.Equal(t, requestScope, consent.Scope)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpEnabled_ConsentIsRequired_ConsentIsPartiallyGranted(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Mandatory,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	// Partially grant consent (only for openid, email, and the second resource/permission)
	resp = postConsent(t, httpClient, redirectLocation, []int{0, 2, 4}, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	// Expected scope after partial consent
	expectedScope := "openid email " + resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, expectedScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	consent, err := database.GetConsentByUserIdAndClientId(nil, user.Id, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, consent)
	assert.Equal(t, user.Id, consent.UserId)
	assert.Equal(t, client.Id, consent.ClientId)
	assertWithinLastXSeconds(t, consent.GrantedAt.Time, 3)
	assert.Equal(t, expectedScope, consent.Scope)
}

func TestAuthorize_NoExistingSession_AcrLevel1_Pwd_ConsentIsRequired_ConsentIsCancelled(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{}, csrf) // Cancel consent
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocationUrl, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocationUrl.Query().Get("error")
	errorDescription := redirectLocationUrl.Query().Get("error_description")

	assert.Equal(t, "access_denied", errorCode)
	assert.Equal(t, "The user did not provide consent", errorDescription)
}

func TestAuthorize_NoExistingSession_AcrLevel2Optional_Pwd_OtpDisabled_ConsentIsRequired_ConsentIsCancelled(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{}, csrf) // Cancel consent
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocationUrl, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocationUrl.Query().Get("error")
	errorDescription := redirectLocationUrl.Query().Get("error_description")

	assert.Equal(t, "access_denied", errorCode)
	assert.Equal(t, "The user did not provide consent", errorDescription)
}

func TestAuthorize_NoExistingSession_AcrLevel2Optional_Pwd_OtpEnabled_ConsentIsRequired_ConsentIsCancelled(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{}, csrf) // Cancel consent
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocationUrl, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocationUrl.Query().Get("error")
	errorDescription := redirectLocationUrl.Query().Get("error_description")

	assert.Equal(t, "access_denied", errorCode)
	assert.Equal(t, "The user did not provide consent", errorDescription)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpDisabled_ConsentIsRequired_ConsentIsCancelled(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Mandatory,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	otpSecret := getOtpSecretFromEnrollmentPage(t, resp)
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{}, csrf) // Cancel consent
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocationUrl, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocationUrl.Query().Get("error")
	errorDescription := redirectLocationUrl.Query().Get("error_description")

	assert.Equal(t, "access_denied", errorCode)
	assert.Equal(t, "The user did not provide consent", errorDescription)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpEnabled_ConsentIsRequired_ConsentIsCancelled(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          enums.AcrLevel2Mandatory,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	resource1 := createResource(t)
	permission1 := createPermission(t, resource1.Id)

	resource2 := createResource(t)
	permission2 := createPermission(t, resource2.Id)

	assignPermissionToUser(t, user.Id, permission1.Id)
	assignPermissionToUser(t, user.Id, permission2.Id)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email " + resource1.ResourceIdentifier + ":" + permission1.PermissionIdentifier + " " +
		resource2.ResourceIdentifier + ":" + permission2.PermissionIdentifier

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	resp = postConsent(t, httpClient, redirectLocation, []int{}, csrf) // Cancel consent
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocationUrl, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	errorCode := redirectLocationUrl.Query().Get("error")
	errorDescription := redirectLocationUrl.Query().Get("error_description")

	assert.Equal(t, "access_denied", errorCode)
	assert.Equal(t, "The user did not provide consent", errorDescription)
}

func TestAuthorize_NoExistingSession_AcrLevel1_Pwd_ConsentIsNotRequired_PasswordIsIncorrect(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel1,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        gofakeit.Email(),
		PasswordHash: passwordHashed,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, "incorrect-password", csrf)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p.text-error").Text()
	assert.Equal(t, "Authentication failed.", errorMsg)

	resp = loadPage(t, httpClient, config.GetAuthServer().BaseURL+"/auth/level1completed")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpDisabled_ConsentIsNotRequired_OtpCodeIsIncorrect(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Mandatory,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPEnabled:   false,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)
	incorrectOtpCode := "123456" // Incorrect OTP code
	resp = authenticateWithOtp(t, httpClient, redirectLocation, incorrectOtpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p.text-error").Text()
	assert.Contains(t, errorMsg, "Incorrect OTP Code")

	// Verify that the user can't proceed to the next step
	resp = loadPage(t, httpClient, config.GetAuthServer().BaseURL+"/auth/completed")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestAuthorize_NoExistingSession_AcrLevel2Mandatory_Pwd_OtpEnabled_ConsentIsNotRequired_OtpIsIncorrect(t *testing.T) {
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          false,
		DefaultAcrLevel:          enums.AcrLevel2Mandatory,
	}

	err := database.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}

	err = database.CreateRedirectURI(nil, redirectUri)
	if err != nil {
		t.Fatal(err)
	}

	password := gofakeit.Password(true, true, true, true, false, 8)
	passwordHashed, err := hashutil.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	userEmail := gofakeit.Email()
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: userEmail,
	})
	if err != nil {
		t.Fatal(err)
	}

	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        userEmail,
		PasswordHash: passwordHashed,
		OTPSecret:    key.Secret(),
		OTPEnabled:   true,
	}

	err = database.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	resp = authenticateWithPassword(t, httpClient, redirectLocation, user.Email, password, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf = getCsrfValue(t, resp)

	incorrectOtpCode := "123456" // Incorrect OTP code
	resp = authenticateWithOtp(t, httpClient, redirectLocation, incorrectOtpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p.text-error").Text()
	assert.Contains(t, errorMsg, "Incorrect OTP Code")

	// Verify that the user can't proceed to the next step
	resp = loadPage(t, httpClient, config.GetAuthServer().BaseURL+"/auth/completed")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestAuthorize_ExistingAcrLevel1Session_AcrLevel1Request(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel1.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel1Session_AcrLevel2OptionalRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	user.OTPEnabled = false
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel1Session_AcrLevel2OptionalRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: user.Email,
	})
	if err != nil {
		t.Fatal(err)
	}

	user.OTPEnabled = true
	user.OTPSecret = key.Secret()
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel1Session_AcrLevel2MandatoryRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	user.OTPEnabled = false
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	otpSecret := getOtpSecretFromEnrollmentPage(t, resp)
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel1Session_AcrLevel2MandatoryRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel1(t)

	// Enable OTP for the user
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: user.Email,
	})
	if err != nil {
		t.Fatal(err)
	}

	user.OTPEnabled = true
	user.OTPSecret = key.Secret()
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel2OptionalSession_AcrLevel1Request(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Optional(t)

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel2OptionalSession_AcrLevel2OptionalRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Optional(t)

	// Ensure OTP is disabled for the user
	user.OTPEnabled = false
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, enums.AuthMethodPassword.String(), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel2OptionalSession_AcrLevel2OptionalRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Optional(t)

	// in this test we simulate an existing session where OTP was disabled,
	// then OTP gets enabled, the user logs in again, and is prompted for OTP

	// Ensure OTP is enabled for the user
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: user.Email,
	})
	if err != nil {
		t.Fatal(err)
	}

	user.OTPEnabled = true
	user.OTPSecret = key.Secret()
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	userSession1.Level2AuthConfigHasChanged = true
	err = database.UpdateUserSession(nil, &userSession1)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)

	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Optional.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	assert.Equal(t, false, userSession2.Level2AuthConfigHasChanged)
}

func TestAuthorize_ExistingAcrLevel2OptionalSession_AcrLevel2MandatoryRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Optional(t)

	// Ensure OTP is disabled for the user
	user.OTPEnabled = false
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	otpSecret := getOtpSecretFromEnrollmentPage(t, resp)
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Verify that OTP is now enabled for the user
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, updatedUser.OTPEnabled)
	assert.NotEmpty(t, updatedUser.OTPSecret)
}

func TestAuthorize_ExistingAcrLevel2OptionalSession_AcrLevel2MandatoryRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Optional(t)

	// Ensure OTP is enabled for the user
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Goiabada",
		AccountName: user.Email,
	})
	if err != nil {
		t.Fatal(err)
	}

	user.OTPEnabled = true
	user.OTPSecret = key.Secret()
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	otpCode, err := totp.GenerateCode(user.OTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Verify that OTP is still enabled for the user
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, updatedUser.OTPEnabled)
	assert.Equal(t, user.OTPSecret, updatedUser.OTPSecret)
}

func TestAuthorize_ExistingAcrLevel2MandatorySession_AcrLevel1Request(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Mandatory(t)

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel1.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)
}

func TestAuthorize_ExistingAcrLevel2MandatorySession_AcrLevel2OptionalRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Mandatory(t)

	// Disable OTP for the user
	user.OTPEnabled = false
	user.OTPSecret = ""
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Verify that the user's OTP settings haven't changed
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.False(t, updatedUser.OTPEnabled)
	assert.Empty(t, updatedUser.OTPSecret)
}

func TestAuthorize_ExistingAcrLevel2MandatorySession_AcrLevel2OptionalRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Mandatory(t)

	// Ensure OTP is enabled for the user
	if !user.OTPEnabled {
		t.Fatal("Expected user to have OTP enabled")
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Optional.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Verify that the user's OTP settings haven't changed
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, updatedUser.OTPEnabled)
	assert.NotEmpty(t, updatedUser.OTPSecret)
}

func TestAuthorize_ExistingAcrLevel2MandatorySession_AcrLevel2MandatoryRequest_OtpDisabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Mandatory(t)

	// Disable OTP for the user
	user.OTPEnabled = false
	user.OTPSecret = ""
	err := database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	userSession1.Level2AuthConfigHasChanged = true
	err = database.UpdateUserSession(nil, &userSession1)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/otp")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	csrf := getCsrfValue(t, resp)
	otpSecret := getOtpSecretFromEnrollmentPage(t, resp)
	otpCode, err := totp.GenerateCode(otpSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp = authenticateWithOtp(t, httpClient, redirectLocation, otpCode, csrf)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Verify that the user's OTP settings have been updated
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, updatedUser.OTPEnabled)
	assert.NotEmpty(t, updatedUser.OTPSecret)
}

func TestAuthorize_ExistingAcrLevel2MandatorySession_AcrLevel2MandatoryRequest_OtpEnabled(t *testing.T) {
	httpClient, client, redirectUri, user := createSessionWithAcrLevel2Mandatory(t)

	// Ensure OTP is enabled for the user
	if !user.OTPEnabled {
		t.Fatal("Expected user to have OTP enabled")
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession1 := userSessions[0]

	time.Sleep(200 * time.Millisecond)

	requestCodeChallenge := gofakeit.LetterN(43)
	requestState := gofakeit.LetterN(8)
	requestNonce := gofakeit.LetterN(8)
	requestScope := "openid profile email"

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + requestCodeChallenge +
		"&scope=" + url.QueryEscape(requestScope) +
		"&state=" + requestState +
		"&nonce=" + requestNonce +
		"&acr_values=" + enums.AcrLevel2Mandatory.String()

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	redirectLocation := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	userSession2 := userSessions[0]

	codeVal, stateVal := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, requestState, stateVal)

	code := loadCodeFromDatabase(t, codeVal)

	assert.Equal(t, client.ClientIdentifier, code.Client.ClientIdentifier)
	assert.Equal(t, requestCodeChallenge, code.CodeChallenge)
	assert.Equal(t, "S256", code.CodeChallengeMethod)
	assert.Equal(t, requestScope, code.Scope)
	assert.Equal(t, requestState, code.State)
	assert.Equal(t, requestNonce, code.Nonce)
	assert.Equal(t, redirectUri.URI, code.RedirectURI)
	assert.Equal(t, user.Id, code.User.Id)
	assert.Equal(t, "query", code.ResponseMode)
	assertWithinLastXSeconds(t, code.AuthenticatedAt, 3)
	assert.Equal(t, enums.AcrLevel2Mandatory.String(), code.AcrLevel)
	assert.Equal(t, fmt.Sprintf("%s %s", enums.AuthMethodPassword.String(), enums.AuthMethodOTP.String()), code.AuthMethods)
	assert.Equal(t, false, code.Used)

	assert.Equal(t, userSession1.Id, userSession2.Id)
	assert.Equal(t, userSession1.SessionIdentifier, userSession2.SessionIdentifier)
	assert.Equal(t, userSession1.Started, userSession2.Started)
	assert.Greater(t, userSession2.LastAccessed, userSession1.LastAccessed)

	// Check that the user's OTP settings remain unchanged
	updatedUser, err := database.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, updatedUser.OTPEnabled)
	assert.Equal(t, user.OTPSecret, updatedUser.OTPSecret)
}
