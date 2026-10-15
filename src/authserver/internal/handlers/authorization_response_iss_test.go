package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/web"
)

// RFC 9207 section 2: an authorization server that advertises
// authorization_response_iss_parameter_supported "MUST" return iss in every authorization response,
// success and error alike, and section 2.4 has a client reject a response without it. iss is the
// issuer setting as read for the request, the value discovery's issuer and every token's iss carry
// (section 2.3), and it follows state, in the order of section 2.1's example (#576, decision 2).
//
// The expected Locations below are written out whole: iss escaped as a query value, after state,
// with nothing after it.

const (
	testResponseIssuer        = "https://issuer.example"
	testResponseIssuerEscaped = "https%3A%2F%2Fissuer.example"
)

// withResponseIssuer is a request whose settings name testResponseIssuer.
func withResponseIssuer(r *http.Request) *http.Request {
	return withSettings(r, &record.Settings{Issuer: testResponseIssuer})
}

func TestAuthorizationResponse_EveryRedirectCarriesIssAfterState(t *testing.T) {
	const callback = "https://example.com/callback"

	for _, tc := range []struct {
		name  string
		write func(w http.ResponseWriter, r *http.Request) error
		want  string
	}{
		{
			name: "a code in the query",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return issueAuthCode(w, r, nil, &record.Code{Code: "c0de", State: "st", RedirectURI: callback}, "query")
			},
			want: callback + "?code=c0de&state=st&iss=" + testResponseIssuerEscaped,
		},
		{
			name: "a code in the default mode, the query",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return issueAuthCode(w, r, nil, &record.Code{Code: "c0de", State: "st", RedirectURI: callback}, "")
			},
			want: callback + "?code=c0de&state=st&iss=" + testResponseIssuerEscaped,
		},
		{
			name: "a code in the fragment",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return issueAuthCode(w, r, nil, &record.Code{Code: "c0de", State: "st", RedirectURI: callback}, "fragment")
			},
			want: callback + "#code=c0de&state=st&iss=" + testResponseIssuerEscaped,
		},
		{
			name: "a code for a request that sent no state",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return issueAuthCode(w, r, nil, &record.Code{Code: "c0de", RedirectURI: callback}, "query")
			},
			want: callback + "?code=c0de&iss=" + testResponseIssuerEscaped,
		},
		{
			name: "implicit tokens in the fragment",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return issueImplicitTokens(w, r, nil, "", callback, "st", &issuance.ImplicitGrantResponse{
					AccessToken: "at", TokenType: "Bearer", ExpiresIn: 60, IdToken: "it", Scope: "openid",
				})
			},
			want: callback + "#access_token=at&token_type=Bearer&expires_in=60&id_token=it&scope=openid&state=st&iss=" +
				testResponseIssuerEscaped,
		},
		{
			name: "an error in the query",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return testClientErrorResponder(testRegisteredDatabase(t, callback), nil, nil).redirToClientWithError(w, r,
					testRedirectError("access_denied", "Access denied", "query", callback, "st", "code"))
			},
			want: callback + "?error=access_denied&error_description=Access+denied&state=st&iss=" + testResponseIssuerEscaped,
		},
		{
			name: "an error in the fragment",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return testClientErrorResponder(testRegisteredDatabase(t, callback), nil, nil).redirToClientWithError(w, r,
					testRedirectError("access_denied", "Access denied", "fragment", callback, "st", "code"))
			},
			want: callback + "#error=access_denied&error_description=Access+denied&state=st&iss=" + testResponseIssuerEscaped,
		},
		{
			name: "an implicit request's error, in the fragment",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return testClientErrorResponder(testRegisteredDatabase(t, callback), nil, nil).redirToClientWithError(w, r,
					testRedirectError("login_required", "Login required", "", callback, "st", "id_token token"))
			},
			want: callback + "#error=login_required&error_description=Login+required&state=st&iss=" + testResponseIssuerEscaped,
		},
		{
			name: "an error for a request that sent no state",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return testClientErrorResponder(testRegisteredDatabase(t, callback), nil, nil).redirToClientWithError(w, r,
					testRedirectError("access_denied", "Access denied", "query", callback, "", "code"))
			},
			want: callback + "?error=access_denied&error_description=Access+denied&iss=" + testResponseIssuerEscaped,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := withResponseIssuer(httptest.NewRequest(http.MethodGet, "/auth/issue", nil))

			require.NoError(t, tc.write(w, r))

			assert.Equal(t, http.StatusFound, w.Code)
			assert.Equal(t, tc.want, w.Header().Get("Location"))
		})
	}
}

// A registered "iss" in the redirect URI's query is the server's own parameter to a client's parser,
// so it is replaced rather than sent beside the real one, on success and on error alike (RFC 6749
// section 3.1: "Request and response parameters MUST NOT be included more than once").
func TestAuthorizationResponse_ARegisteredIssIsReplaced(t *testing.T) {
	const registered = "https://example.com/callback?iss=https%3A%2F%2Fevil.example&lang=en"

	t.Run("a code", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withResponseIssuer(httptest.NewRequest(http.MethodGet, "/auth/issue", nil))

		require.NoError(t, issueAuthCode(w, r, nil, &record.Code{Code: "c0de", State: "st", RedirectURI: registered}, "query"))

		assert.Equal(t, "https://example.com/callback?lang=en&code=c0de&state=st&iss="+testResponseIssuerEscaped,
			w.Header().Get("Location"))
	})

	t.Run("an error", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withResponseIssuer(httptest.NewRequest(http.MethodGet, "/auth/authorize", nil))

		require.NoError(t, testClientErrorResponder(testRegisteredDatabase(t, registered), nil, nil).redirToClientWithError(w, r,
			testRedirectError("access_denied", "Access denied", "query", registered, "st", "code")))

		assert.Equal(t, "https://example.com/callback?lang=en&error=access_denied&error_description=Access+denied&state=st&iss="+
			testResponseIssuerEscaped, w.Header().Get("Location"))
	})
}

// hiddenInputPattern reads the built-in form_post page's hidden inputs, in the order they are posted.
var hiddenInputPattern = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)" />`)

// formPostFields is the page's hidden inputs as name and value pairs, in page order.
func formPostFields(body string) [][2]string {
	var fields [][2]string
	for _, match := range hiddenInputPattern.FindAllStringSubmatch(body, -1) {
		fields = append(fields, [2]string{match[1], match[2]})
	}
	return fields
}

// The form_post page carries iss too, after state, for each of the three outcomes.
func TestAuthorizationResponse_EveryFormPostCarriesIssAfterState(t *testing.T) {
	const callback = "https://example.com/callback"

	for _, tc := range []struct {
		name  string
		write func(w http.ResponseWriter, r *http.Request) error
		want  [][2]string
	}{
		{
			name: "a code",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return issueAuthCode(w, r, web.TemplateFS(), &record.Code{Code: "c0de", State: "st", RedirectURI: callback}, "form_post")
			},
			want: [][2]string{{"code", "c0de"}, {"state", "st"}, {"iss", testResponseIssuer}},
		},
		{
			name: "implicit tokens",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return issueImplicitTokens(w, r, web.TemplateFS(), "form_post", callback, "st", &issuance.ImplicitGrantResponse{
					AccessToken: "at", TokenType: "Bearer", ExpiresIn: 60, IdToken: "it", Scope: "openid",
				})
			},
			want: [][2]string{{"access_token", "at"}, {"token_type", "Bearer"}, {"expires_in", "60"}, {"id_token", "it"},
				{"scope", "openid"}, {"state", "st"}, {"iss", testResponseIssuer}},
		},
		{
			name: "an error",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return testClientErrorResponder(testRegisteredDatabase(t, callback), nil, web.TemplateFS()).redirToClientWithError(w, r,
					testRedirectError("access_denied", "Access denied", "form_post", callback, "st", "code"))
			},
			want: [][2]string{{"error", "access_denied"}, {"error_description", "Access denied"}, {"state", "st"},
				{"iss", testResponseIssuer}},
		},
		{
			name: "a code for a request that sent no state",
			write: func(w http.ResponseWriter, r *http.Request) error {
				return issueAuthCode(w, r, web.TemplateFS(), &record.Code{Code: "c0de", RedirectURI: callback}, "form_post")
			},
			want: [][2]string{{"code", "c0de"}, {"iss", testResponseIssuer}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := withResponseIssuer(httptest.NewRequest(http.MethodGet, "/auth/issue", nil))

			require.NoError(t, tc.write(w, r))

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tc.want, formPostFields(w.Body.String()))
		})
	}
}

// A request that reaches an emitter without its settings has no issuer to send, and a response
// without iss is one RFC 9207 section 2.4 has the client reject, so nothing is written and the caller
// answers 500. Every handler reads the settings before it gets this far, so this is the last resort.
func TestAuthorizationResponse_WithoutSettingsNothingIsWritten(t *testing.T) {
	const callback = "https://example.com/callback"

	for _, mode := range []string{"query", "fragment", "form_post"} {
		t.Run(mode, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/auth/issue", nil)

			err := issueAuthCode(w, r, web.TemplateFS(), &record.Code{Code: "c0de", State: "st", RedirectURI: callback}, mode)

			require.Error(t, err)
			assert.Empty(t, w.Header().Get("Location"))
			assert.Empty(t, w.Header().Get("Cache-Control"))
			assert.Empty(t, w.Body.String())
		})
	}
}

// The responder the route table builds renders form_post.html from the built-in templates, which
// carry iss, so an operator's template directory holding a copy from an older release cannot drop
// it: NewClientErrorResponder takes no template set to be handed one (#576, decision 5). The code
// and the implicit tokens are written through the same responder's page at /auth/issue.
func TestNewClientErrorResponder_TheFormPostPageIsTheBuiltInOne(t *testing.T) {
	const callback = "https://example.com/callback"
	w := httptest.NewRecorder()
	r := withResponseIssuer(httptest.NewRequest(http.MethodGet, "/auth/authorize", nil))

	responder := NewClientErrorResponder(testRegisteredDatabase(t, callback), nil)
	require.NoError(t, responder.redirToClientWithError(w, r,
		testRedirectError("login_required", "Login required", "form_post", callback, "st", "code")))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `<form method="post" action="https://example.com/callback">`)
	assert.Equal(t, [][2]string{{"error", "login_required"}, {"error_description", "Login required"}, {"state", "st"},
		{"iss", testResponseIssuer}}, formPostFields(w.Body.String()))
}
