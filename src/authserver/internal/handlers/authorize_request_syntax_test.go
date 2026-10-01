package handlers

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
)

// These cases are the handler's half of #244's remaining parts: the authorization endpoint hands the
// validator the request as asked for and stores the scope the response type honours, and it answers
// each new refusal through the deferral path like every other. They run over the real
// AuthorizeValidator, because a stub that answers "unsupported" shows only the redirect and nothing
// about what the handler passes it. Every accepted and refused spelling is protocolvalidation's
// table; each outcome reaches its act once here.

// newSyntaxAuthorizeEndpoint is HandleAuthorizeGet over the real validator, for a client that may use
// the implicit grant as well as the code flow.
func newSyntaxAuthorizeEndpoint(t *testing.T) *authorizeEndpoint {
	t.Helper()
	e := newAuthorizeEndpoint(t)
	e.handler = HandleAuthorizeGet(e.pageRenderer, e.ceremonyStore, e.userSessionManager, e.database, nil,
		protocolvalidation.NewAuthorizeValidator(e.database), mocks_handlers.NewAuditLogger(t),
		mocks_handlers.NewPermissionChecker(t), mocks_handlers.NewTokenParser(t), testBaseURL)

	implicit := true
	client := &models.Client{
		Id: 1, ClientIdentifier: "test-client", Enabled: true, AuthorizationCodeEnabled: true,
		ImplicitGrantEnabled: &implicit, DefaultAcrLevel: models.AcrLevel1,
	}
	e.database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)
	e.database.On("ClientLoadRedirectURIs", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			args.Get(2).(*models.Client).RedirectURIs = []models.RedirectURI{{URI: "https://example.com"}}
		}).Return(nil)
	stubRegisteredRedirectURI(e.database, "https://example.com")
	return e
}

// syntaxQuery is a request whose parameters a case overrides. An implicit id_token needs a nonce and
// the openid scope, so the defaults serve every response type.
func syntaxQuery(overrides map[string]string) string {
	query := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"https://example.com"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"s"},
		"nonce":         {"n"},
	}
	for name, value := range overrides {
		query.Set(name, value)
	}
	return query.Encode()
}

// parkedBy runs the request for a logged-out browser and answers the context the handler parked, so a
// case can read the refusal it carries.
func parkedBy(t *testing.T, e *authorizeEndpoint, query string) *ceremony.AuthContext {
	t.Helper()
	e.stubLoggedOutBrowser()
	var saved *ceremony.AuthContext
	e.ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { saved = args.Get(2).(*ceremony.AuthContext) }).Return(nil).Once()

	rr := e.get(t, query)

	assertStepLocation(t, rr.Header().Get("Location"), "/auth/level1")
	require.NotNil(t, saved, "the request was neither parked nor sent to the login")
	return saved
}

// answeredAtOnceTo runs the request for a session holder and answers the redirect it was given,
// which is where the refusal is on the wire (#213).
func answeredAtOnceTo(t *testing.T, e *authorizeEndpoint, query string) *url.URL {
	t.Helper()
	stubAuthenticatedBrowser(e.database, e.userSessionManager)
	e.ceremonyStore.On("ClearAuthContext", mock.Anything, mock.Anything).Return(nil).Once()

	rr := e.get(t, query)

	require.Equal(t, http.StatusFound, rr.Code)
	location, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "example.com", location.Host)
	return location
}

// TestHandleAuthorizeGet_OfflineAccessIsHonouredOnlyWithACode is OIDC Core 11 at the endpoint:
// offline_access is stored for a response type that returns a code and is ignored for one that does
// not, in the scope the ceremony carries and in the one a restart restores, so it cannot come back
// onto an implicit ceremony through a restart.
func TestHandleAuthorizeGet_OfflineAccessIsHonouredOnlyWithACode(t *testing.T) {
	cases := []struct {
		responseType string
		scope        string
		want         string
	}{
		{"code", "openid offline_access", "openid offline_access"},
		{"code", "offline_access openid", "offline_access openid"},
		{"token", "openid offline_access", "openid"},
		{"token", "offline_access openid profile", "openid profile"},
		{"id_token", "openid offline_access", "openid"},
		{"id_token token", "openid offline_access", "openid"},
		{"token id_token", "openid offline_access", "openid"},
		// A resource scope that merely holds the text is not offline_access and stays.
		{"token", "openid res:offline_access_read", ""},
	}

	for _, tc := range cases {
		t.Run(tc.responseType+" with "+tc.scope, func(t *testing.T) {
			e := newSyntaxAuthorizeEndpoint(t)
			if tc.want == "" {
				// The resource scope is looked up as any other, so an unknown one is refused for being
				// unknown: this row shows only that the text is not mistaken for offline_access, and
				// what the endpoint stores is asserted for the rows above.
				e.database.On("GetResourceByResourceIdentifier", mock.Anything, mock.Anything, "res").
					Return(&models.Resource{Id: 1}, nil)
				e.database.On("GetPermissionsByResourceId", mock.Anything, mock.Anything, int64(1)).
					Return([]models.Permission{{PermissionIdentifier: "offline_access_read"}}, nil)
				tc.want = "openid res:offline_access_read"
			}

			saved := parkedBy(t, e, syntaxQuery(map[string]string{"response_type": tc.responseType, "scope": tc.scope}))

			assert.Empty(t, saved.DeferredErrorCode, "the request was refused")
			assert.Equal(t, tc.want, saved.Scope)
			assert.Equal(t, tc.want, saved.RequestedScope, "a restart restores the honoured scope, not the asked one")
		})
	}
}

// TestHandleAuthorizeGet_OfflineAccessAloneIsRefusedOnEveryResponseType: a request for offline_access
// and nothing else names no resource and no claim. It is refused for what it is, also where the
// response type would have ignored it and left the scope empty, and not called missing.
func TestHandleAuthorizeGet_OfflineAccessAloneIsRefusedOnEveryResponseType(t *testing.T) {
	const description = "The 'scope' parameter holds only 'offline_access', which grants nothing by itself. Include at least one other scope, such as 'openid' or a resource:permission scope."

	for _, responseType := range []string{"code", "token"} {
		t.Run(responseType+", parked for a logged-out browser", func(t *testing.T) {
			e := newSyntaxAuthorizeEndpoint(t)

			saved := parkedBy(t, e, syntaxQuery(map[string]string{"response_type": responseType, "scope": "offline_access"}))

			assert.Equal(t, "invalid_scope", saved.DeferredErrorCode)
			assert.Equal(t, description, saved.DeferredErrorDescription)
		})
	}

	// An id_token needs the openid scope whatever else is asked, and that refusal comes first, so
	// these are refused before the scope's own rule is reached. Pinned so that the order is a choice.
	for _, responseType := range []string{"id_token", "id_token token"} {
		t.Run(responseType+" is refused for the missing openid scope first", func(t *testing.T) {
			e := newSyntaxAuthorizeEndpoint(t)

			saved := parkedBy(t, e, syntaxQuery(map[string]string{"response_type": responseType, "scope": "offline_access"}))

			assert.Equal(t, "invalid_request", saved.DeferredErrorCode)
			assert.Equal(t, "The 'openid' scope is required when requesting an id_token.", saved.DeferredErrorDescription)
		})
	}

	t.Run("code, answered at once to a session holder", func(t *testing.T) {
		e := newSyntaxAuthorizeEndpoint(t)

		location := answeredAtOnceTo(t, e, syntaxQuery(map[string]string{"scope": "offline_access"}))

		assert.Equal(t, "invalid_scope", location.Query().Get("error"))
		assert.Equal(t, description, location.Query().Get("error_description"))
	})

	t.Run("token, answered at once in the fragment", func(t *testing.T) {
		e := newSyntaxAuthorizeEndpoint(t)

		location := answeredAtOnceTo(t, e, syntaxQuery(map[string]string{"response_type": "token", "scope": "offline_access"}))

		fragment, err := url.ParseQuery(location.Fragment)
		require.NoError(t, err)
		assert.Equal(t, "invalid_scope", fragment.Get("error"))
		assert.Equal(t, description, fragment.Get("error_description"))
	})
}

// TestHandleAuthorizeGet_ResponseTypeSpellingsAreRefusedThroughDeferral: a response_type repeating a
// value or naming an unknown one is unsupported_response_type, answered as every refusal here is,
// at once to a session holder and parked behind a login for a browser without one.
func TestHandleAuthorizeGet_ResponseTypeSpellingsAreRefusedThroughDeferral(t *testing.T) {
	const description = "The authorization server does not support this response_type. Supported values: code, token, id_token, id_token token."

	for _, responseType := range []string{"code code", "code foo", "foo code", "code token"} {
		t.Run(responseType+", parked", func(t *testing.T) {
			e := newSyntaxAuthorizeEndpoint(t)

			saved := parkedBy(t, e, syntaxQuery(map[string]string{"response_type": responseType}))

			assert.Equal(t, "unsupported_response_type", saved.DeferredErrorCode)
			assert.Equal(t, description, saved.DeferredErrorDescription)
		})

		t.Run(responseType+", answered at once", func(t *testing.T) {
			e := newSyntaxAuthorizeEndpoint(t)

			location := answeredAtOnceTo(t, e, syntaxQuery(map[string]string{"response_type": responseType}))

			assert.Equal(t, "unsupported_response_type", location.Query().Get("error"))
			assert.Equal(t, description, location.Query().Get("error_description"))
		})
	}

	// The control: the spelling with the second word removed is the code flow and proceeds, so it is
	// the repeated or unknown word that was refused.
	t.Run("code alone proceeds to the login", func(t *testing.T) {
		e := newSyntaxAuthorizeEndpoint(t)

		saved := parkedBy(t, e, syntaxQuery(nil))

		assert.Empty(t, saved.DeferredErrorCode)
		assert.Equal(t, ceremony.AuthStateRequiresLevel1, saved.AuthState)
	})
}

// TestHandleAuthorizeGet_SelectAccountIsAnsweredAsUnsupported: a known prompt value the server cannot
// honour is refused as account_selection_required through the deferral path, where it used to be
// invalid_request for an unknown value.
func TestHandleAuthorizeGet_SelectAccountIsAnsweredAsUnsupported(t *testing.T) {
	const description = "prompt=select_account is not supported: the authorization server cannot ask the end user to select an account."

	t.Run("parked for a logged-out browser", func(t *testing.T) {
		e := newSyntaxAuthorizeEndpoint(t)

		saved := parkedBy(t, e, syntaxQuery(map[string]string{"prompt": "select_account"}))

		assert.Equal(t, "account_selection_required", saved.DeferredErrorCode)
		assert.Equal(t, description, saved.DeferredErrorDescription)
	})

	t.Run("answered at once to a session holder", func(t *testing.T) {
		e := newSyntaxAuthorizeEndpoint(t)

		location := answeredAtOnceTo(t, e, syntaxQuery(map[string]string{"prompt": "select_account"}))

		assert.Equal(t, "account_selection_required", location.Query().Get("error"))
		assert.Equal(t, description, location.Query().Get("error_description"))
	})

	// With login beside it the browser is sent to log in whatever session it holds, and the refusal
	// is parked behind that login (#213), so it is the same refusal delivered later. A
	// prompt=login request reads no session at all, so none is stubbed.
	t.Run("beside login, parked whatever session the browser holds", func(t *testing.T) {
		e := newSyntaxAuthorizeEndpoint(t)
		var saved *ceremony.AuthContext
		e.ceremonyStore.On("SaveAuthContext", mock.Anything, mock.Anything, mock.Anything).
			Run(func(args mock.Arguments) { saved = args.Get(2).(*ceremony.AuthContext) }).Return(nil).Once()

		rr := e.get(t, syntaxQuery(map[string]string{"prompt": "select_account login"}))

		assertStepLocation(t, rr.Header().Get("Location"), "/auth/level1")
		require.NotNil(t, saved)
		assert.Equal(t, "account_selection_required", saved.DeferredErrorCode)
	})
}

// TestHandleAuthorizeGet_SilenceIsReadThroughTheSharedSplitter: the handler decides a request is
// silent from the raw prompt, and reads it with the validator's splitter, on the space alone. A
// space between two values is a separator and both are seen; a tab or a no-break space is not, and
// the two words are one unknown value. A malformed prompt is still split, so one that asks for none
// with a space too many is silent and refused for its grammar at once. A silent request is answered
// at once whoever is at the browser; one that is not is parked (#244).
func TestHandleAuthorizeGet_SilenceIsReadThroughTheSharedSplitter(t *testing.T) {
	// answeredAtOnce follows the redirect a silent request gets. No browser is stubbed: a silent
	// request reads no session here and is answered at once, which is what shows it was seen as
	// silent and not parked behind a login.
	answeredAtOnce := func(t *testing.T, prompt string) url.Values {
		t.Helper()
		e := newSyntaxAuthorizeEndpoint(t)
		e.ceremonyStore.On("ClearAuthContext", mock.Anything, mock.Anything).Return(nil).Once()

		rr := e.get(t, syntaxQuery(map[string]string{"prompt": prompt}))

		require.Equal(t, http.StatusFound, rr.Code)
		location, err := url.Parse(rr.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "example.com", location.Host)
		return location.Query()
	}

	t.Run("none and login joined by a space is silent, and refused as the combination it is", func(t *testing.T) {
		answer := answeredAtOnce(t, "none login")
		assert.Equal(t, "invalid_request", answer.Get("error"))
		assert.Equal(t, "prompt=none cannot be combined with other values", answer.Get("error_description"))
	})

	for _, prompt := range []string{"none ", " none", "none  login"} {
		t.Run("a malformed prompt asking for none is silent, and refused as malformed: "+prompt, func(t *testing.T) {
			answer := answeredAtOnce(t, prompt)
			assert.Equal(t, "invalid_request", answer.Get("error"))
			assert.Equal(t, "The 'prompt' parameter is malformed. Separate its values with a single space, with no space before the first value or after the last.",
				answer.Get("error_description"))
		})
	}

	// A tab used to separate, which made this silent (#244).
	t.Run("none and login joined by a tab is one unknown value and is not silent", func(t *testing.T) {
		e := newSyntaxAuthorizeEndpoint(t)

		saved := parkedBy(t, e, syntaxQuery(map[string]string{"prompt": "none\tlogin"}))

		assert.Equal(t, "invalid_request", saved.DeferredErrorCode)
		assert.Contains(t, saved.DeferredErrorDescription, "Invalid prompt value:")
	})

	t.Run("none and login joined by a no-break space is one unknown value and is not silent", func(t *testing.T) {
		e := newSyntaxAuthorizeEndpoint(t)

		saved := parkedBy(t, e, syntaxQuery(map[string]string{"prompt": "none login"}))

		assert.Equal(t, "invalid_request", saved.DeferredErrorCode)
		assert.Contains(t, saved.DeferredErrorDescription, "Invalid prompt value:")
	})
}
