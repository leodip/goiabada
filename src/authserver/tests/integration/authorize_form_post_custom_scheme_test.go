package integration

import (
	"context"
	"io"
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

// response_mode=form_post answers through an HTML form whose action is the redirect URI, and
// html/template rewrites a private-use scheme (RFC 8252 section 7.1) there to "#ZgotmplZ", so the
// form posted the code back to this server and nothing reached the app (#121). An error answered in
// that mode goes the same way, so the request is answered on the refusal page, 400, with no form,
// as an unsupported response_mode is (OIDC Core 1.0 section 3.1.2.6), whether or not the browser
// holds a session and whatever prompt says.

// The page's text, byte for byte, so a reword of the catalog shows here.
const (
	formPostUnreachableCode = "response_mode=form_post posts the response to the redirect URI as a form, " +
		"which no scheme other than http or https can receive. Use response_mode=query or response_mode=fragment instead."
	formPostUnreachableImplicit = "response_mode=form_post posts the response to the redirect URI as a form, " +
		"which no scheme other than http or https can receive. Use response_mode=fragment instead."
)

const (
	formPostCustomSchemeURI = "myapp://callback"
	formPostRFC8252URI      = "com.example.app:/oauth2redirect/example-provider"
	formPostHTTPSURI        = "https://form-post.example.com/callback"
)

// newFormPostClient is a client with both flows on and the three redirect URIs above registered, so
// a refusal is the scheme's and nothing else's.
func newFormPostClient(t *testing.T) *record.Client {
	t.Helper()
	implicit := true
	client := &record.Client{
		ClientIdentifier:         "form-post-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ImplicitGrantEnabled:     &implicit,
		DefaultAcrLevel:          record.AcrLevel1,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	for _, uri := range []string{formPostCustomSchemeURI, formPostRFC8252URI, formPostHTTPSURI} {
		require.NoError(t, database.CreateRedirectURI(context.Background(), nil,
			&record.RedirectURI{ClientId: client.Id, URI: uri}))
	}
	return client
}

func formPostAuthorizeParams(client *record.Client, responseType, responseMode, redirectURI, prompt string) url.Values {
	params := url.Values{
		"client_id":             {client.ClientIdentifier},
		"redirect_uri":          {redirectURI},
		"response_type":         {responseType},
		"code_challenge_method": {"S256"},
		"code_challenge":        {fake.LetterN(43)},
		"scope":                 {"openid"},
		"state":                 {fake.LetterN(8)},
		"nonce":                 {fake.LetterN(8)},
	}
	if responseMode != "" {
		params.Set("response_mode", responseMode)
	}
	if prompt != "" {
		params.Set("prompt", prompt)
	}
	return params
}

// assertFormPostRefusalPage asserts the response is the refusal page carrying want: a 400, no
// Location, no form, and nothing the template's URL filter wrote.
func assertFormPostRefusalPage(t *testing.T, resp *http.Response, want string) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "the refusal is a page, not a redirect")
	assert.NotContains(t, string(body), "<form", "no form is rendered to post anything anywhere")
	assert.NotContains(t, string(body), "ZgotmplZ")

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	require.NoError(t, err)
	assert.Equal(t, want, strings.TrimSpace(doc.Find("#errorMsg").Text()))
}

func TestAuthorize_FormPostToAPrivateUseSchemeIsRefusedOnThePage(t *testing.T) {
	client := newFormPostClient(t)

	for _, tc := range []struct {
		name         string
		responseType string
		redirectURI  string
		prompt       string
		want         string
	}{
		{name: "code, myapp://", responseType: "code", redirectURI: formPostCustomSchemeURI, want: formPostUnreachableCode},
		{name: "code, RFC 8252 reverse domain", responseType: "code", redirectURI: formPostRFC8252URI, want: formPostUnreachableCode},
		{name: "code, prompt=none", responseType: "code", redirectURI: formPostCustomSchemeURI, prompt: "none", want: formPostUnreachableCode},
		{name: "token", responseType: "token", redirectURI: formPostCustomSchemeURI, want: formPostUnreachableImplicit},
		{name: "id_token token", responseType: "id_token token", redirectURI: formPostRFC8252URI, want: formPostUnreachableImplicit},
	} {
		t.Run("GET "+tc.name, func(t *testing.T) {
			params := formPostAuthorizeParams(client, tc.responseType, "form_post", tc.redirectURI, tc.prompt)
			resp := loadPage(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/auth/authorize?"+params.Encode())
			defer func() { _ = resp.Body.Close() }()

			assertFormPostRefusalPage(t, resp, tc.want)
		})

		t.Run("POST "+tc.name, func(t *testing.T) {
			resp := crossSitePost(t, formPostAuthorizeParams(client, tc.responseType, "form_post", tc.redirectURI, tc.prompt))
			defer func() { _ = resp.Body.Close() }()

			assertFormPostRefusalPage(t, resp, tc.want)
		})
	}
}

// The controls: form_post to an https redirect URI, and the query to a private-use one, begin the
// ceremony as before, at the login page.
func TestAuthorize_FormPostToHTTPSAndQueryToAPrivateUseSchemeBeginTheCeremony(t *testing.T) {
	client := newFormPostClient(t)

	for _, tc := range []struct {
		name         string
		responseMode string
		redirectURI  string
	}{
		{name: "form_post to https", responseMode: "form_post", redirectURI: formPostHTTPSURI},
		{name: "query to myapp://", responseMode: "query", redirectURI: formPostCustomSchemeURI},
		{name: "no response_mode to myapp://", redirectURI: formPostCustomSchemeURI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := formPostAuthorizeParams(client, "code", tc.responseMode, tc.redirectURI, "")
			resp := loadPage(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/auth/authorize?"+params.Encode())
			defer func() { _ = resp.Body.Close() }()

			assertRedirect(t, resp, "/auth/level1")
		})
	}
}
