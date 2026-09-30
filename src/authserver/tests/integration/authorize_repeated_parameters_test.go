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
// once." A parameter repeated with differing values is refused at both endpoints; identical copies
// proceed (#228, #437 decision 18). What counts as a conflict is protocolvalidation's table; these
// show each answer reaching the wire.

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

	t.Run("a second client_id in the query", func(t *testing.T) {
		query := repeatedParametersQuery(client, redirectUri)
		query.Add("client_id", "some-other-client")

		resp, err := createAuthenticatedHttpClient(t).Get(appConfig.AuthServer.BaseURL + "/auth/authorize/?" + query.Encode())
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, "The client_id parameter was included more than once with different values.",
			refusalPageMessage(t, resp))
	})

	// r.Form merges a POST body and the query, so one copy in each is the same violation.
	t.Run("one redirect_uri in a POST body and another in the query", func(t *testing.T) {
		form := repeatedParametersQuery(client, redirectUri)
		req, err := http.NewRequest(http.MethodPost,
			appConfig.AuthServer.BaseURL+"/auth/authorize?redirect_uri="+url.QueryEscape("https://attacker.example/cb"),
			strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := createHttpClient(t).Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, "The redirect_uri parameter was included more than once with different values.",
			refusalPageMessage(t, resp))
	})

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

	t.Run("a differing nonce, with state echoed", func(t *testing.T) {
		query := repeatedParametersQuery(client, redirectUri)
		query.Add("nonce", "another-nonce")

		location := answer(t, query)

		assert.Equal(t, redirectUri.URI, location.Scheme+"://"+location.Host+location.Path)
		assert.Equal(t, "invalid_request", location.Query().Get("error"))
		assert.Equal(t, "The 'nonce' parameter was included more than once with different values.",
			location.Query().Get("error_description"))
		assert.Equal(t, query["state"], location.Query()["state"])
	})

	// RFC 6749 4.1.2 returns "the exact value received"; with two there is none, so none is sent.
	t.Run("a differing state is left out of the redirect", func(t *testing.T) {
		query := repeatedParametersQuery(client, redirectUri)
		query.Add("state", "another-state")

		location := answer(t, query)

		assert.Equal(t, "invalid_request", location.Query().Get("error"))
		assert.NotContains(t, location.Query(), "state")
	})

	// Decision 18's leniency: identical copies leave one value, and the sign-in goes on with it.
	t.Run("identical copies proceed", func(t *testing.T) {
		query := repeatedParametersQuery(client, redirectUri)
		for _, name := range []string{"client_id", "redirect_uri", "scope", "state", "nonce"} {
			query.Add(name, query.Get(name))
		}

		location := answer(t, query)

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

	t.Run("a differing client_secret is invalid_request", func(t *testing.T) {
		status, body := post(t, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {"wrong-secret", clientSecret},
		})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_request", body["error"])
		assert.Equal(t, "The 'client_secret' parameter was included more than once with different values.", body["error_description"])
	})

	t.Run("a differing grant_type is invalid_request", func(t *testing.T) {
		status, body := post(t, url.Values{
			"grant_type":    {"client_credentials", "password"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {clientSecret},
		})
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_request", body["error"])
		assert.Contains(t, body["error_description"], "'grant_type'")
	})

	t.Run("identical copies proceed", func(t *testing.T) {
		status, body := post(t, url.Values{
			"grant_type":    {"client_credentials", "client_credentials"},
			"client_id":     {client.ClientIdentifier, client.ClientIdentifier},
			"client_secret": {clientSecret, clientSecret},
		})
		assert.Equal(t, http.StatusOK, status, "%v", body)
		assert.NotEmpty(t, body["access_token"])
	})
}
