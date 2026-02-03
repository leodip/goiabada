package integrationtests

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

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
	assert.Equal(t, "The response_type parameter is missing.", errorDescription)
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

	assert.Equal(t, "unsupported_response_type", errorCode)
	assert.Equal(t, "The authorization server does not support this response_type. Supported values: code, token, id_token, id_token token.", errorDescription)
}

func TestAuthorize_ValidateRequest_CodeChallengeMethodIsMissing(t *testing.T) {
	pkceRequired := true
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		PKCERequired:             &pkceRequired,
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
	pkceRequired := true
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		PKCERequired:             &pkceRequired,
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
	pkceRequired := true
	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		PKCERequired:             &pkceRequired,
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
		pkceRequired := true
		client := &models.Client{
			ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
			Enabled:                  true,
			AuthorizationCodeEnabled: true,
			PKCERequired:             &pkceRequired,
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
