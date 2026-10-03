package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

// The implicit flow's response mode (#231, decision 15). A request for a response type that returns
// tokens may ask for the fragment, for form_post, or for nothing, and never for the query: OAuth 2.0
// Multiple Response Type Encoding Practices sections 3 and 5 say "the query encoding MUST NOT be
// used" for id_token and id_token token, and OAuth 2.0 Form Post Response Mode section 4 says it is
// safe to return the parameters whose default is the fragment using form_post.
//
// The rule has one home, implicitResponseMode, which the success path (issueImplicitTokens) and the
// error path (redirToClientWithError) both read; the validator's refusal of an explicit query is
// protocolvalidation's own table. What is here is the handler half: the table of the rule, the
// form_post branch of the success path, and the error emitter answering the refusal in the fragment.

// implicitTokenResponse is a response carrying every parameter the fragment carries.
func implicitTokenResponse() *issuance.ImplicitGrantResponse {
	return &issuance.ImplicitGrantResponse{
		AccessToken: "access-token-123",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		IdToken:     "id-token-123",
		Scope:       "openid profile",
	}
}

// TestImplicitResponseMode is the rule's whole table, no handler and no mocks. The query row is the
// one that matters: it is a mode this server implements and the request may not use for tokens, and
// the answer is the fragment so that the refusal of that very request reaches the client where an
// implicit client reads it. An absent mode is the fragment, the default for these response types.
func TestImplicitResponseMode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested string
		want      string
	}{
		{name: "absent is the fragment, the default", requested: "", want: "fragment"},
		{name: "fragment is the fragment", requested: "fragment", want: "fragment"},
		{name: "form_post is honoured", requested: "form_post", want: "form_post"},
		{name: "query is never used for tokens", requested: "query", want: "fragment"},
		{name: "a mode nothing implements is not honoured", requested: "jwt", want: "fragment"},
		{name: "the value is case sensitive, as the validator's is", requested: "Form_Post", want: "fragment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, implicitResponseMode(tc.requested))
		})
	}
}

// The form_post branch of issueImplicitTokens, rendered with the real template because a stub is what
// lets a template that omits a token go unnoticed: form_post.html carried the code and the error
// fields only until #231, so an implicit form_post response through it would have been an empty form.
func TestIssueImplicitTokens_FormPost(t *testing.T) {
	// The four fields a fragment response carries besides the token type are asserted in every row,
	// so a template that fails to render a field cannot pass a row asserting its absence elsewhere.
	t.Run("every token parameter is a hidden input, and nothing is redirected", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withSessionSettings(httptest.NewRequest("GET", "/auth/issue?ceremony="+testCeremonyId, nil))

		err := issueImplicitTokens(w, r, web.TemplateFS(), "form_post", "https://example.com/callback",
			"client-csrf-token", implicitTokenResponse())

		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Location"), "form_post answers with a page, not a redirect")
		body := w.Body.String()
		assert.Contains(t, body, `<form method="post" action="https://example.com/callback">`)
		assert.Contains(t, body, `<input type="hidden" name="access_token" value="access-token-123" />`)
		assert.Contains(t, body, `<input type="hidden" name="token_type" value="Bearer" />`)
		assert.Contains(t, body, `<input type="hidden" name="expires_in" value="3600" />`)
		assert.Contains(t, body, `<input type="hidden" name="id_token" value="id-token-123" />`)
		assert.Contains(t, body, `<input type="hidden" name="scope" value="openid profile" />`)
		assert.Contains(t, body, `<input type="hidden" name="state" value="client-csrf-token" />`)
		assert.NotContains(t, body, `name="code"`, "a token response must not carry an authorization code")
		assert.NotContains(t, body, `name="error"`)
	})

	// OAuth 2.0 Form Post Response Mode section 2: "the Authorization Server MUST instruct the User
	// Agent (and any intermediaries) not to store or reuse the content of the response". The page
	// holds the tokens themselves here, which is why the pair is asserted for this emitter and not
	// left to writeFormPost's own tests.
	t.Run("the page is not to be stored", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withSessionSettings(httptest.NewRequest("GET", "/auth/issue?ceremony="+testCeremonyId, nil))

		err := issueImplicitTokens(w, r, web.TemplateFS(), "form_post", "https://example.com/callback", "s",
			implicitTokenResponse())

		require.NoError(t, err)
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
	})

	// The response's parameters follow the fragment's rules: each is present when it has a value.
	t.Run("only the parameters the grant produced", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			response *issuance.ImplicitGrantResponse
			present  []string
			absent   []string
		}{
			{
				name:     "token",
				response: &issuance.ImplicitGrantResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 60, Scope: "openid"},
				present:  []string{"access_token", "token_type", "expires_in", "scope"},
				absent:   []string{"id_token"},
			},
			{
				name:     "id_token",
				response: &issuance.ImplicitGrantResponse{IdToken: "it", Scope: "openid"},
				present:  []string{"id_token", "scope"},
				absent:   []string{"access_token", "token_type", "expires_in"},
			},
			{
				name:     "id_token token",
				response: &issuance.ImplicitGrantResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 60, IdToken: "it"},
				present:  []string{"access_token", "token_type", "expires_in", "id_token"},
				absent:   []string{"scope"},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				r := withSessionSettings(httptest.NewRequest("GET", "/auth/issue?ceremony="+testCeremonyId, nil))

				err := issueImplicitTokens(w, r, web.TemplateFS(), "form_post", "https://example.com/callback", "s", tc.response)

				require.NoError(t, err)
				body := w.Body.String()
				for _, name := range tc.present {
					assert.Contains(t, body, `name="`+name+`"`, "%s is part of this response", name)
				}
				for _, name := range tc.absent {
					assert.NotContains(t, body, `name="`+name+`"`, "%s is not part of this response", name)
				}
			})
		}
	})

	// The bind map holds exactly the parameters the fragment would carry, so an operator-supplied
	// template that enumerates it sees the same set (#146), and an absent state is absent rather than
	// empty.
	t.Run("the bind map holds the redirect URI and the parameters, and no absent state", func(t *testing.T) {
		const keysTemplate = `{{range $k, $v := .}}[{{$k}}]{{end}}`
		for _, tc := range []struct {
			name  string
			state string
			want  string
		}{
			{name: "a state the client sent", state: "abc123",
				want: `[access_token][expires_in][id_token][redirectURI][scope][state][token_type]`},
			{name: "a whitespace-only state", state: "   ",
				want: `[access_token][expires_in][id_token][redirectURI][scope][state][token_type]`},
			{name: "no state at all", state: "",
				want: `[access_token][expires_in][id_token][redirectURI][scope][token_type]`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				r := withSessionSettings(httptest.NewRequest("GET", "/auth/issue?ceremony="+testCeremonyId, nil))
				templateFS := fstest.MapFS{"form_post.html": {Data: []byte(keysTemplate)}}

				err := issueImplicitTokens(w, r, templateFS, "form_post", "https://example.com/callback",
					tc.state, implicitTokenResponse())

				require.NoError(t, err)
				assert.Equal(t, tc.want, w.Body.String())
			})
		}
	})

	t.Run("the real template omits an absent state and echoes a whitespace-only one", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withSessionSettings(httptest.NewRequest("GET", "/auth/issue?ceremony="+testCeremonyId, nil))
		err := issueImplicitTokens(w, r, web.TemplateFS(), "form_post", "https://example.com/callback", "",
			implicitTokenResponse())
		require.NoError(t, err)
		assert.NotContains(t, w.Body.String(), `name="state"`)

		w = httptest.NewRecorder()
		err = issueImplicitTokens(w, r, web.TemplateFS(), "form_post", "https://example.com/callback", "   ",
			implicitTokenResponse())
		require.NoError(t, err)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="state" value="   " />`)
	})

	// A state is the client's own string, and the page it is written into is HTML. html/template
	// escapes it in the attribute, so a state carrying a quote and a tag cannot close the input and
	// open an element of its own on a page that holds the tokens.
	t.Run("a state that is markup is escaped in the attribute", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withSessionSettings(httptest.NewRequest("GET", "/auth/issue?ceremony="+testCeremonyId, nil))

		err := issueImplicitTokens(w, r, web.TemplateFS(), "form_post", "https://example.com/callback",
			`"><script>alert(1)</script>`, implicitTokenResponse())

		require.NoError(t, err)
		body := w.Body.String()
		assert.NotContains(t, body, "<script>")
		assert.Contains(t, body, "&lt;script&gt;")
	})

	// Gate 4 sits above the response-mode dispatch, so it covers form_post exactly as it covers the
	// fragment (issueAuthCode's comment carries why). The stake is the tokens themselves, and the
	// form's action is the one place html/template passes a scheme-relative value through untouched:
	// "//evil.example/cb" as a form action would post the tokens to evil.example.
	//
	// Each row varies only the redirect URI from the passing row above, and each names the gate that
	// refuses it. Nothing is rendered, so no header is written and the caller's 500 owns the response.
	t.Run("a redirect URI that is not an absolute URI is refused, in form_post too", func(t *testing.T) {
		for _, redirectURI := range []string{
			"//evil.example/cb",
			"https:///evil.example/cb",
			"/relative/cb",
			"https://legit.example/cb#frag",
		} {
			t.Run(redirectURI, func(t *testing.T) {
				w := httptest.NewRecorder()
				r := withSessionSettings(httptest.NewRequest("GET", "/auth/issue?ceremony="+testCeremonyId, nil))

				err := issueImplicitTokens(w, r, web.TemplateFS(), "form_post", redirectURI, "s", implicitTokenResponse())

				assert.Error(t, err, "checkRedirectURIEmittable must refuse %q before the form is built", redirectURI)
				assert.Empty(t, w.Body.String(), "no page may be written")
				assert.NotContains(t, w.Body.String(), "access-token-123")
				assert.Empty(t, w.Header().Get("Cache-Control"), "nothing was rendered, so no header was written")
			})
		}
	})

	// A template that cannot be rendered leaves the response untouched, so the caller's last-resort
	// 500 is the only answer and no partial page carrying a token is committed (#141).
	t.Run("a template that cannot render leaves the response uncommitted", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withSessionSettings(httptest.NewRequest("GET", "/auth/issue?ceremony="+testCeremonyId, nil))

		err := issueImplicitTokens(w, r, fstest.MapFS{}, "form_post", "https://example.com/callback", "s",
			implicitTokenResponse())

		assert.Error(t, err)
		assert.Empty(t, w.Body.String())
		assert.Empty(t, w.Header().Get("Cache-Control"))
	})
}

// The fragment stays the answer for everything that is not form_post, and the query is not
// reachable from the success path whatever the ceremony holds: the mode is implicitResponseMode's,
// so a ceremony stored with an explicit query (which ValidateRequest refuses, so none is) would still
// not put a token in the query component.
func TestIssueImplicitTokens_FragmentIsTheDefault(t *testing.T) {
	for _, mode := range []string{"", "fragment", "query", "jwt"} {
		t.Run("response_mode="+mode, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := withSessionSettings(httptest.NewRequest("GET", "/auth/issue?ceremony="+testCeremonyId, nil))

			err := issueImplicitTokens(w, r, nil, mode, "https://example.com/callback", "test-state",
				implicitTokenResponse())

			require.NoError(t, err)
			assert.Equal(t, http.StatusFound, w.Code)
			assert.Equal(t,
				"https://example.com/callback#access_token=access-token-123&token_type=Bearer&expires_in=3600&id_token=id-token-123&scope=openid+profile&state=test-state",
				w.Header().Get("Location"))
		})
	}
}

// The handler half: /auth/issue reads the ceremony's response mode and hands it to the emitter, so
// an implicit ceremony that asked for form_post is answered with the form and the ceremony is
// cleared before the tokens leave, as it is for the fragment. The issuer, the audit event and the
// registration gate are the fragment case's, unchanged.
func TestHandleIssueGet_ImplicitFlow_FormPost(t *testing.T) {
	pageRenderer := handlersmocks.NewPageRenderer(t)
	ceremonyStore := handlersmocks.NewCeremonyStore(t)
	codeIssuer := handlersmocks.NewCodeIssuer(t)
	implicitTokenIssuer := handlersmocks.NewImplicitTokenIssuer(t)
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	userSessionManager := handlersmocks.NewUserSessionManager(t)
	permissionChecker := handlersmocks.NewPermissionChecker(t)

	handler := HandleIssueGet(pageRenderer, ceremonyStore, web.TemplateFS(), codeIssuer, implicitTokenIssuer, database,
		auditLogger, userSessionManager, permissionChecker, testBaseURL, testAdminConsoleBaseURL)

	req := requestWithSessionIdentifier(t, liveSessionIdentifier)
	rr := httptest.NewRecorder()

	authContext := &ceremony.AuthContext{
		CeremonyId:   testCeremonyId,
		AuthState:    ceremony.AuthStateReadyToIssueCode,
		ClientId:     "test-client",
		UserId:       123,
		ResponseMode: "form_post",
		ResponseType: "id_token token",
		RedirectURI:  "https://example.com/callback",
		Scope:        "openid",
		State:        "test-state",
		Nonce:        "test-nonce",
		AcrLevel:     "urn:goiabada:pwd",
		AuthMethods:  "pwd",
	}
	ceremonyStore.On("GetAuthContext", req).Return(authContext, nil)

	database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").
		Return(&record.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true, AuthorizationCodeEnabled: true, ImplicitGrantEnabled: &implicitAllowed}, nil)
	database.On("GetUserById", mock.Anything, mock.Anything, int64(123)).
		Return(&record.User{Id: 123, Subject: "11111111-1111-1111-1111-111111111111", Enabled: true}, nil)

	implicitTokenIssuer.On("IssueImplicitTx", mock.Anything, mock.Anything, mock.Anything, true, true).
		Return(implicitTokenResponse(), nil)
	auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedImplicitResponse, mock.Anything).Return()

	// The context is cleared, and only then does the response go out.
	ceremonyStore.On("ClearAuthContext", rr, req).Return(nil)

	stubLiveSession(database, 123)
	armIssueGate(database, userSessionManager, permissionChecker, authContext.RedirectURI)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, rr.Header().Get("Location"))
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	body := rr.Body.String()
	assert.Contains(t, body, `<form method="post" action="https://example.com/callback">`)
	assert.Contains(t, body, `<input type="hidden" name="access_token" value="access-token-123" />`)
	assert.Contains(t, body, `<input type="hidden" name="id_token" value="id-token-123" />`)
	assert.Contains(t, body, `<input type="hidden" name="state" value="test-state" />`)

	pageRenderer.AssertExpectations(t)
	ceremonyStore.AssertExpectations(t)
	implicitTokenIssuer.AssertExpectations(t)
	auditLogger.AssertExpectations(t)
}

// The error emitter's half. An implicit request's error is delivered in the fragment, or in the
// form_post the request asked for; an explicit query is answered in the fragment as well, which is
// the delivery the refusal of that request needs (#231). Before, the emitter let an explicit query
// through to the query component, so the refusal of a request for tokens in the query arrived in
// the query.
func TestRedirToClientWithError_ImplicitFlow_QueryIsAnsweredInTheFragment(t *testing.T) {
	for _, responseType := range []string{"token", "id_token", "id_token token", "token id_token"} {
		t.Run(responseType, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/authorize", nil)

			err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil,
				testRedirectError("invalid_request", "Implicit flow does not support response_mode=query.", "query",
					"https://example.com/callback", "state123", responseType))

			require.NoError(t, err)
			assert.Equal(t, http.StatusFound, w.Code)
			location := w.Header().Get("Location")
			assert.Contains(t, location, "https://example.com/callback#error=invalid_request")
			assert.Contains(t, location, "state=state123")
			assert.NotContains(t, location, "?", "nothing may be written into the query component")
		})
	}

	// The same row against the code flow, which still honours an explicit query: only a response
	// type returning tokens is moved.
	t.Run("a code request's explicit query is still the query", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/authorize", nil)

		err := redirToClientWithError(w, r, testRegisteredDatabase(t, "https://example.com/callback"), nil, nil,
			testRedirectError("access_denied", "Access denied", "query", "https://example.com/callback", "state123", "code"))

		require.NoError(t, err)
		assert.Contains(t, w.Header().Get("Location"), "https://example.com/callback?error=access_denied")
	})
}
