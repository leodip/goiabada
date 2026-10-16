package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 9207 over HTTP (#576, decision 2). Discovery advertises
// authorization_response_iss_parameter_supported, and every authorization response then carries
// iss, in the query, the fragment and form_post, on success and on error, equal to the issuer
// discovery names (RFC 9207 section 2.4: the client compares the two "using simple string
// comparison"). iss follows state, as in section 2.1's example.

// discoveryIssuer reads the issuer the discovery document names, and checks the document advertises
// iss in authorization responses.
func discoveryIssuer(t *testing.T) string {
	t.Helper()
	resp, body := fetchDiscoveryAt(t, "/.well-known/openid-configuration", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var document struct {
		Issuer                string `json:"issuer"`
		IssParameterSupported *bool  `json:"authorization_response_iss_parameter_supported"`
	}
	require.NoError(t, json.Unmarshal(body, &document), string(body))
	require.NotEmpty(t, document.Issuer)
	require.NotNil(t, document.IssParameterSupported, "discovery advertises the flag: %s", body)
	require.True(t, *document.IssParameterSupported)
	return document.Issuer
}

// issParam is the field every authorization response ends with, for a test that compares a whole
// Location: iss, escaped as a query value, after state.
func issParam(t *testing.T) string {
	t.Helper()
	return "&iss=" + url.QueryEscape(discoveryIssuer(t))
}

// assertIssLast checks a raw query or fragment: iss appears once, equal to issuer, as the last field,
// with state, when the request sent one, right before it.
func assertIssLast(t *testing.T, raw string, issuer string, state string) {
	t.Helper()
	values, err := url.ParseQuery(raw)
	require.NoError(t, err, raw)
	assert.Equal(t, []string{issuer}, values["iss"], raw)

	fields := strings.Split(raw, "&")
	assert.Equal(t, "iss="+url.QueryEscape(issuer), fields[len(fields)-1], "iss is the last field: %s", raw)
	if state != "" {
		require.GreaterOrEqual(t, len(fields), 2, raw)
		assert.Equal(t, "state="+url.QueryEscape(state), fields[len(fields)-2], "state precedes iss: %s", raw)
	}
}

// formPostNames reads a form_post page's hidden inputs in page order, as names and values.
func formPostNames(t *testing.T, resp *http.Response) (names []string, values map[string]string) {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	values = map[string]string{}
	doc.Find("form input[type='hidden']").Each(func(_ int, input *goquery.Selection) {
		name := input.AttrOr("name", "")
		names = append(names, name)
		values[name] = input.AttrOr("value", "")
	})
	return names, values
}

// silentCodeURL is a prompt=none code request in responseMode.
func silentCodeURL(clientIdentifier, redirectURI, state, responseMode string) string {
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + clientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + fake.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + state +
		"&prompt=none"
	if responseMode != "" {
		destUrl += "&response_mode=" + responseMode
	}
	return destUrl
}

func TestAuthorizationResponseIss_ACodeCarriesTheDiscoveryIssuer(t *testing.T) {
	issuer := discoveryIssuer(t)

	for _, mode := range []string{"", "query", "fragment", "form_post"} {
		t.Run("mode "+mode, func(t *testing.T) {
			httpClient, client, redirectUri, _ := createSessionWithAcrLevel1(t)
			state := fake.LetterN(12)

			resp, err := httpClient.Get(silentCodeURL(client.ClientIdentifier, redirectUri.URI, state, mode))
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			resp = loadPage(t, httpClient, assertRedirect(t, resp, "/auth/issue"))
			defer func() { _ = resp.Body.Close() }()

			switch mode {
			case "form_post":
				require.Equal(t, http.StatusOK, resp.StatusCode)
				names, values := formPostNames(t, resp)
				assert.Equal(t, []string{"code", "state", "iss"}, names)
				assert.Equal(t, state, values["state"])
				assert.Equal(t, issuer, values["iss"])
			case "fragment":
				require.Equal(t, http.StatusFound, resp.StatusCode)
				location, err := url.Parse(resp.Header.Get("Location"))
				require.NoError(t, err)
				assertIssLast(t, location.EscapedFragment(), issuer, state)
			default:
				require.Equal(t, http.StatusFound, resp.StatusCode)
				location, err := url.Parse(resp.Header.Get("Location"))
				require.NoError(t, err)
				assert.NotEmpty(t, location.Query().Get("code"))
				assertIssLast(t, location.RawQuery, issuer, state)
			}
		})
	}
}

func TestAuthorizationResponseIss_AnErrorCarriesTheDiscoveryIssuer(t *testing.T) {
	issuer := discoveryIssuer(t)

	// prompt=none with no session: login_required, answered at once.
	for _, mode := range []string{"", "query", "fragment", "form_post"} {
		t.Run("mode "+mode, func(t *testing.T) {
			client, redirectUri := createTestClientAndRedirectURI(t)
			state := fake.LetterN(12)

			resp, err := createHttpClient(t).Get(silentCodeURL(client.ClientIdentifier, redirectUri.URI, state, mode))
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			switch mode {
			case "form_post":
				require.Equal(t, http.StatusOK, resp.StatusCode)
				names, values := formPostNames(t, resp)
				assert.Equal(t, []string{"error", "error_description", "state", "iss"}, names)
				assert.Equal(t, "login_required", values["error"])
				assert.Equal(t, issuer, values["iss"])
			case "fragment":
				require.Equal(t, http.StatusFound, resp.StatusCode)
				location, err := url.Parse(resp.Header.Get("Location"))
				require.NoError(t, err)
				assertIssLast(t, location.EscapedFragment(), issuer, state)
			default:
				require.Equal(t, http.StatusFound, resp.StatusCode)
				location, err := url.Parse(resp.Header.Get("Location"))
				require.NoError(t, err)
				assert.Equal(t, "login_required", location.Query().Get("error"))
				assertIssLast(t, location.RawQuery, issuer, state)
			}
		})
	}
}

func TestAuthorizationResponseIss_ImplicitTokensCarryTheDiscoveryIssuer(t *testing.T) {
	enableImplicitFlowGlobally(t)
	issuer := discoveryIssuer(t)

	for _, mode := range []string{"fragment", "form_post"} {
		t.Run(mode, func(t *testing.T) {
			client, redirectUri := createImplicitFlowClient(t, nil)
			user, password := createTestUserForImplicit(t)
			state := fake.LetterN(12)

			resp := signInToIssue(t, createHttpClient(t),
				implicitModeAuthorizeURL(client, redirectUri.URI, "id_token token", mode, state, fake.LetterN(12)),
				user, password)
			defer func() { _ = resp.Body.Close() }()

			if mode == "form_post" {
				require.Equal(t, http.StatusOK, resp.StatusCode)
				names, values := formPostNames(t, resp)
				assert.Equal(t, []string{"access_token", "token_type", "expires_in", "id_token", "scope", "state", "iss"}, names)
				assert.Equal(t, issuer, values["iss"])
				return
			}
			require.Equal(t, http.StatusFound, resp.StatusCode)
			location, err := url.Parse(resp.Header.Get("Location"))
			require.NoError(t, err)
			assert.NotEmpty(t, location.Fragment)
			assertIssLast(t, location.EscapedFragment(), issuer, state)
		})
	}
}

// The issuer is the setting as read for the request: a changed issuer reaches the next response and
// discovery alike, with no restart.
func TestAuthorizationResponseIss_FollowsTheIssuerSetting(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)
	changed := discoveryIssuer(t) + "/changed"
	changeSettings(t, func(s *record.Settings) { s.Issuer = changed })

	require.Equal(t, changed, discoveryIssuer(t))

	state := fake.LetterN(12)
	resp, err := createHttpClient(t).Get(silentCodeURL(client.ClientIdentifier, redirectUri.URI, state, "query"))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assertIssLast(t, location.RawQuery, changed, state)
}
