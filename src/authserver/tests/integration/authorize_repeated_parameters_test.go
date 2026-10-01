package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
)

// RFC 6749 sections 3.1 and 3.2: "Request and response parameters MUST NOT be included more than
// once." A repeated parameter is refused at both endpoints, whether or not its copies agree (#228).
// What counts as a repeat is protocolvalidation's table; these show each answer reaching the wire.

// repeatedParametersQuery is a code-flow request for client, as a url.Values so a case can add a
// second copy of any parameter.
func repeatedParametersQuery(client *models.Client, redirectUri *models.RedirectURI) url.Values {
	return url.Values{
		"client_id":             {client.ClientIdentifier},
		"redirect_uri":          {redirectUri.URI},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {fake.LetterN(43)},
		"scope":                 {"openid"},
		"state":                 {fake.LetterN(8)},
		"nonce":                 {fake.LetterN(8)},
	}
}

// refusalPageMessage reads the refusal page's message, requiring a 400 with no redirect.
func refusalPageMessage(t *testing.T, resp *http.Response) string {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	require.Empty(t, resp.Header.Get("Location"), "the page is the whole answer; nothing is redirected")
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	return doc.Find("p#errorMsg").Text()
}

func TestAuthorize_RepeatedParameters_DeliveryParameterIsRefusedOnThePage(t *testing.T) {
	client, redirectUri := createTestClientWithRedirect(t)

	for _, tc := range []struct{ name, second string }{
		{"a second, differing client_id in the query", "some-other-client"},
		{"a second, identical client_id in the query", client.ClientIdentifier},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := repeatedParametersQuery(client, redirectUri)
			query.Add("client_id", tc.second)

			resp, err := createAuthenticatedHttpClient(t).Get(appConfig.AuthServer.BaseURL + "/auth/authorize/?" + query.Encode())
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, "The client_id parameter was included more than once.", refusalPageMessage(t, resp))
		})
	}

	// r.Form merges a POST body and the query, so one copy in each is the same violation.
	for _, tc := range []struct{ name, inQuery string }{
		{"one redirect_uri in a POST body and another in the query", "https://attacker.example/cb"},
		{"one redirect_uri in a POST body and the same one in the query", redirectUri.URI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := repeatedParametersQuery(client, redirectUri)
			req, err := http.NewRequest(http.MethodPost,
				appConfig.AuthServer.BaseURL+"/auth/authorize?redirect_uri="+url.QueryEscape(tc.inQuery),
				strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := createHttpClient(t).Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, "The redirect_uri parameter was included more than once.", refusalPageMessage(t, resp))
		})
	}

	// Before #228 the parse failure was ignored and the field carrying it silently dropped.
	t.Run("a parameter that is not correctly encoded", func(t *testing.T) {
		query := repeatedParametersQuery(client, redirectUri)

		resp, err := createAuthenticatedHttpClient(t).Get(appConfig.AuthServer.BaseURL + "/auth/authorize/?" +
			query.Encode() + "&ui_locales=%zz")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, "The authorization request could not be read: one of its parameters is not correctly encoded.",
			refusalPageMessage(t, resp))
	})
}

func TestAuthorize_RepeatedParameters_OtherParameterIsInvalidRequest(t *testing.T) {
	client, redirectUri := createTestClientWithRedirect(t)

	// A session holder is answered at once (#213), so the refusal is on the redirect itself.
	answer := func(t *testing.T, query url.Values) *url.URL {
		t.Helper()
		resp, err := createAuthenticatedHttpClient(t).Get(appConfig.AuthServer.BaseURL + "/auth/authorize/?" + query.Encode())
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusFound, resp.StatusCode)
		location, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		return location
	}

	for _, tc := range []struct{ name, second string }{
		{"a differing nonce, with state echoed", "another-nonce"},
		{"an identical nonce, with state echoed", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := repeatedParametersQuery(client, redirectUri)
			second := tc.second
			if second == "" {
				second = query.Get("nonce")
			}
			query.Add("nonce", second)

			location := answer(t, query)

			assert.Equal(t, redirectUri.URI, location.Scheme+"://"+location.Host+location.Path)
			assert.Equal(t, "invalid_request", location.Query().Get("error"))
			assert.Equal(t, "The 'nonce' parameter was included more than once.", location.Query().Get("error_description"))
			assert.Equal(t, query["state"][:1], location.Query()["state"])
		})
	}

	// RFC 6749 4.1.2 returns "the exact value received"; a repeated state was not received as one
	// value, whether or not the copies agree, so none is sent.
	for _, tc := range []struct{ name, second string }{
		{"a differing state is left out of the redirect", "another-state"},
		{"an identical state is left out of the redirect", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := repeatedParametersQuery(client, redirectUri)
			second := tc.second
			if second == "" {
				second = query.Get("state")
			}
			query.Add("state", second)

			location := answer(t, query)

			assert.Equal(t, "invalid_request", location.Query().Get("error"))
			assert.Equal(t, "The 'state' parameter was included more than once.", location.Query().Get("error_description"))
			assert.NotContains(t, location.Query(), "state")
		})
	}

	// Identical copies used to proceed (#228). One copy of every parameter is the control the rows
	// above vary from: the session holder's sign-in goes on.
	t.Run("identical copies of a scope are refused", func(t *testing.T) {
		query := repeatedParametersQuery(client, redirectUri)
		query.Add("scope", query.Get("scope"))

		location := answer(t, query)

		assert.Equal(t, "invalid_request", location.Query().Get("error"))
		assert.Equal(t, "The 'scope' parameter was included more than once.", location.Query().Get("error_description"))
	})

	t.Run("one copy of each goes on", func(t *testing.T) {
		location := answer(t, repeatedParametersQuery(client, redirectUri))

		assert.Equal(t, "/auth/level1completed", location.Path, "the session holder's sign-in goes on: %v", location)
	})
}

func TestToken_RepeatedParameters(t *testing.T) {
	clientSecret := fake.Password(32)
	clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	client := &models.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          models.AcrLevel1,
		ClientSecretEncrypted:    clientSecretEncrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	resource := createResourceWithId(t, "repeated-svc-"+fake.LetterN(8))
	permission := createPermissionWithId(t, resource.Id, "read-"+fake.LetterN(8))
	require.NoError(t, database.CreateClientPermission(context.Background(), nil, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permission.Id,
	}))

	post := func(t *testing.T, form url.Values) (int, map[string]interface{}) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+"/auth/token/", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := createHttpClient(t).Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		return resp.StatusCode, body
	}

	refused := []struct {
		name, parameter string
		form            url.Values
	}{
		{"a differing client_secret", "client_secret", url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {"wrong-secret", clientSecret},
		}},
		{"a differing grant_type", "grant_type", url.Values{
			"grant_type":    {"client_credentials", "password"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {clientSecret},
		}},
		// Identical copies used to be issued a token (#228).
		{"an identical client_secret", "client_secret", url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {clientSecret, clientSecret},
		}},
		{"an identical grant_type", "grant_type", url.Values{
			"grant_type":    {"client_credentials", "client_credentials"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {clientSecret},
		}},
		{"an identical scope", "scope", url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {clientSecret},
			"scope":         {resource.ResourceIdentifier + ":" + permission.PermissionIdentifier, resource.ResourceIdentifier + ":" + permission.PermissionIdentifier},
		}},
	}
	for _, tc := range refused {
		t.Run(tc.name+" is invalid_request", func(t *testing.T) {
			status, body := post(t, tc.form)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, "invalid_request", body["error"])
			assert.Equal(t, "The '"+tc.parameter+"' parameter was included more than once.", body["error_description"])
			assert.NotContains(t, body, "access_token")
		})
	}

	t.Run("one copy of each is issued a token", func(t *testing.T) {
		status, body := post(t, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {clientSecret},
			"scope":         {resource.ResourceIdentifier + ":" + permission.PermissionIdentifier},
		})
		assert.Equal(t, http.StatusOK, status, "%v", body)
		assert.NotEmpty(t, body["access_token"])
	})
}
