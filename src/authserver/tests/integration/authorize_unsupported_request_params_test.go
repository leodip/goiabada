package integrationtests

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func createTestClientWithRedirect(t *testing.T) (*models.Client, *models.RedirectURI) {
	t.Helper()

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}
	if err := database.CreateClient(nil, client); err != nil {
		t.Fatal(err)
	}

	redirectUri := &models.RedirectURI{
		ClientId: client.Id,
		URI:      gofakeit.URL(),
	}
	if err := database.CreateRedirectURI(nil, redirectUri); err != nil {
		t.Fatal(err)
	}

	return client, redirectUri
}

func TestAuthorize_RequestParameter_RejectedAsUnsupported(t *testing.T) {
	client, redirectUri := createTestClientWithRedirect(t)

	state := gofakeit.LetterN(8)

	params := url.Values{}
	params.Set("client_id", client.ClientIdentifier)
	params.Set("redirect_uri", redirectUri.URI)
	params.Set("response_type", "code")
	params.Set("scope", "openid")
	params.Set("state", state)
	params.Set("request", "some.jwt.value")

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?" + params.Encode()

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

	assert.Equal(t, "request_not_supported", redirectLocation.Query().Get("error"))
	assert.Equal(t, state, redirectLocation.Query().Get("state"))
}

func TestAuthorize_RequestParameter_EmptyValue_RejectedAsUnsupported(t *testing.T) {
	client, redirectUri := createTestClientWithRedirect(t)

	params := url.Values{}
	params.Set("client_id", client.ClientIdentifier)
	params.Set("redirect_uri", redirectUri.URI)
	params.Set("response_type", "code")
	params.Set("scope", "openid")
	// Encoded form drops the value but keeps the key, so request= still has the key present.
	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?" + params.Encode() + "&request="

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

	assert.Equal(t, "request_not_supported", redirectLocation.Query().Get("error"))
}

func TestAuthorize_RequestUriParameter_RejectedAsUnsupported(t *testing.T) {
	client, redirectUri := createTestClientWithRedirect(t)

	state := gofakeit.LetterN(8)

	params := url.Values{}
	params.Set("client_id", client.ClientIdentifier)
	params.Set("redirect_uri", redirectUri.URI)
	params.Set("response_type", "code")
	params.Set("scope", "openid")
	params.Set("state", state)
	params.Set("request_uri", "https://example.com/req.jwt")

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?" + params.Encode()

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

	assert.Equal(t, "request_uri_not_supported", redirectLocation.Query().Get("error"))
	assert.Equal(t, state, redirectLocation.Query().Get("state"))
}

func TestAuthorize_RequestParameter_PostBody_RejectedAsUnsupported(t *testing.T) {
	client, redirectUri := createTestClientWithRedirect(t)

	form := url.Values{}
	form.Set("client_id", client.ClientIdentifier)
	form.Set("redirect_uri", redirectUri.URI)
	form.Set("response_type", "code")
	form.Set("scope", "openid")
	form.Set("state", gofakeit.LetterN(8))
	form.Set("request", "some.jwt.value")

	destURL := config.GetAuthServer().BaseURL + "/auth/authorize"

	req, err := http.NewRequest(http.MethodPost, destURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://www.certification.openid.net")

	httpClient := createHttpClient(t)
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)

	redirectLocation, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "request_not_supported", redirectLocation.Query().Get("error"))
}

func TestAuthorize_RequestParameter_InvalidClient_RendersErrorUi(t *testing.T) {
	params := url.Values{}
	params.Set("client_id", "does_not_exist")
	params.Set("redirect_uri", "https://example.com")
	params.Set("response_type", "code")
	params.Set("scope", "openid")
	params.Set("request", "some.jwt.value")

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?" + params.Encode()

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	// No redirect; error UI is rendered when client_id is invalid.
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "Invalid client_id parameter. The client does not exist.", errorMsg)
}

func TestAuthorize_RequestParameter_RejectedAcrossResponseModes(t *testing.T) {
	t.Run("query response mode", func(t *testing.T) {
		client, redirectUri := createTestClientWithRedirect(t)
		state := gofakeit.LetterN(8)

		params := url.Values{}
		params.Set("client_id", client.ClientIdentifier)
		params.Set("redirect_uri", redirectUri.URI)
		params.Set("response_type", "code")
		params.Set("scope", "openid")
		params.Set("state", state)
		params.Set("response_mode", "query")
		params.Set("request", "some.jwt.value")

		destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?" + params.Encode()

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
		assert.Equal(t, "request_not_supported", redirectLocation.Query().Get("error"))
		assert.Equal(t, state, redirectLocation.Query().Get("state"))
	})

	t.Run("fragment response mode", func(t *testing.T) {
		client, redirectUri := createTestClientWithRedirect(t)
		state := gofakeit.LetterN(8)

		params := url.Values{}
		params.Set("client_id", client.ClientIdentifier)
		params.Set("redirect_uri", redirectUri.URI)
		params.Set("response_type", "code")
		params.Set("scope", "openid")
		params.Set("state", state)
		params.Set("response_mode", "fragment")
		params.Set("request", "some.jwt.value")

		destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?" + params.Encode()

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
		assert.Equal(t, "request_not_supported", fragment.Get("error"))
		assert.Equal(t, state, fragment.Get("state"))
	})

	t.Run("form_post response mode", func(t *testing.T) {
		client, redirectUri := createTestClientWithRedirect(t)
		state := gofakeit.LetterN(8)

		params := url.Values{}
		params.Set("client_id", client.ClientIdentifier)
		params.Set("redirect_uri", redirectUri.URI)
		params.Set("response_type", "code")
		params.Set("scope", "openid")
		params.Set("state", state)
		params.Set("response_mode", "form_post")
		params.Set("request", "some.jwt.value")

		destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?" + params.Encode()

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
		assert.True(t, exists)
		assert.Equal(t, redirectUri.URI, formAction)

		assert.Equal(t, "request_not_supported", doc.Find("input[name='error']").AttrOr("value", ""))
		assert.Equal(t, state, doc.Find("input[name='state']").AttrOr("value", ""))
	})
}

func TestAuthorize_RequestUriParameter_RejectedAcrossResponseModes(t *testing.T) {
	// One run for request_uri to confirm the second branch behaves the same;
	// we exercise fragment mode since query is already covered by the
	// non-matrix request_uri test above.
	client, redirectUri := createTestClientWithRedirect(t)
	state := gofakeit.LetterN(8)

	params := url.Values{}
	params.Set("client_id", client.ClientIdentifier)
	params.Set("redirect_uri", redirectUri.URI)
	params.Set("response_type", "code")
	params.Set("scope", "openid")
	params.Set("state", state)
	params.Set("response_mode", "fragment")
	params.Set("request_uri", "https://example.com/req.jwt")

	destUrl := config.GetAuthServer().BaseURL + "/auth/authorize/?" + params.Encode()

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
	assert.Equal(t, "request_uri_not_supported", fragment.Get("error"))
	assert.Equal(t, state, fragment.Get("state"))
}
