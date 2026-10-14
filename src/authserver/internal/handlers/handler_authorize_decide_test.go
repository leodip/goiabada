package handlers

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

// authorizeWorld is what HandleAuthorizeGet would load, answered from the row instead of from a
// database, so a decideAuthorizeRoute case is a table row with no HTTP harness and no mocks.
type authorizeWorld struct {
	silent, login           bool // the raw prompt's none and login tokens
	emitted                 bool
	sessionValid            bool
	refused                 bool
	promptNone, promptLogin bool // the validated prompt's
	hint                    string
	userSubject             string
	userEnabled             bool
}

// driveAuthorizeRoute runs decideAuthorizeRoute as HandleAuthorizeGet does, loading each fact it
// asks for from the world, and answers the route and the facts in the order they were asked for.
func driveAuthorizeRoute(t *testing.T, world authorizeWorld) (authorizeRoute, []authorizeFact) {
	t.Helper()

	facts := authorizeRouteFacts{requestsSilence: world.silent, requestsLogin: world.login}
	var asked []authorizeFact
	for {
		route, need := decideAuthorizeRoute(facts)
		if need == authorizeFactNone {
			require.NotEqual(t, authorizeRouteUndecided, route, "a decided request has a route")
			return route, asked
		}
		require.NotContains(t, asked, need, "each fact is loaded once")
		asked = append(asked, need)

		switch need {
		case authorizeFactRedirectEmission:
			emitted := world.emitted
			facts.redirectEmitted = &emitted
		case authorizeFactSessionValidity:
			valid := world.sessionValid
			facts.sessionValid = &valid
		case authorizeFactValidation:
			facts.validated = true
			facts.refused = world.refused
			facts.promptNone = world.promptNone
			facts.promptLogin = world.promptLogin
			facts.hintSubject = world.hint
		case authorizeFactSessionUser:
			facts.sessionUserLoaded = true
			facts.sessionUserSubject = world.userSubject
			facts.sessionUserEnabled = world.userEnabled
		default:
			require.FailNow(t, "an unknown fact", "%v", need)
		}
	}
}

// Every route /auth/authorize can take, and the reads each makes. The handler cases show each
// route reaching its act; which route a request takes, and what it reads on the way, is decided
// here (#437 seam 1). The reads are part of the answer: a silent request never reads the
// registration table or the session here, a withheld redirect or prompt=login never reads the
// session before validating, and a session read failing answers 500 before a refusal can be
// answered, because it comes first (#213, #241).
func TestDecideAuthorizeRoute(t *testing.T) {
	const (
		emission   = authorizeFactRedirectEmission
		session    = authorizeFactSessionValidity
		validation = authorizeFactValidation
		user       = authorizeFactSessionUser
	)

	testCases := []struct {
		name      string
		world     authorizeWorld
		wantRoute authorizeRoute
		wantReads []authorizeFact
	}{
		// A refused request: answered now or parked behind a login (RFC 9700 4.11.2, #213).
		{
			name:      "a refused silent request is answered now, reading neither the registration nor the session",
			world:     authorizeWorld{silent: true, emitted: true, refused: true},
			wantRoute: authorizeRouteAnswerNow,
			wantReads: []authorizeFact{validation},
		},
		{
			// ValidatePrompt refuses "none login", and the raw none still makes it silent.
			name:      "a refused none login is silent and answered now",
			world:     authorizeWorld{silent: true, login: true, emitted: true, refused: true},
			wantRoute: authorizeRouteAnswerNow,
			wantReads: []authorizeFact{validation},
		},
		{
			name:      "a refused request whose redirect is withheld is answered now, without reading the session",
			world:     authorizeWorld{emitted: false, sessionValid: false, refused: true},
			wantRoute: authorizeRouteAnswerNow,
			wantReads: []authorizeFact{emission, validation},
		},
		{
			name:      "a refused request from a valid session is answered now",
			world:     authorizeWorld{emitted: true, sessionValid: true, refused: true},
			wantRoute: authorizeRouteAnswerNow,
			wantReads: []authorizeFact{emission, session, validation},
		},
		{
			name:      "a refused request with no valid session is parked",
			world:     authorizeWorld{emitted: true, sessionValid: false, refused: true},
			wantRoute: authorizeRoutePark,
			wantReads: []authorizeFact{emission, session, validation},
		},
		{
			// The session would say yes; prompt=login asks not to be answered on its strength.
			name:      "a refused prompt=login request is parked, without reading the session",
			world:     authorizeWorld{login: true, emitted: true, sessionValid: true, refused: true},
			wantRoute: authorizeRoutePark,
			wantReads: []authorizeFact{emission, validation},
		},

		// An accepted request.
		{
			name:      "prompt=none goes to silent authentication, which reads the session itself",
			world:     authorizeWorld{silent: true, emitted: true, sessionValid: true, promptNone: true},
			wantRoute: authorizeRoutePromptNone,
			wantReads: []authorizeFact{validation},
		},
		{
			name:      "prompt=login forces a login and never reads the session",
			world:     authorizeWorld{login: true, emitted: true, sessionValid: true, promptLogin: true, userEnabled: true},
			wantRoute: authorizeRouteForceLogin,
			wantReads: []authorizeFact{emission, validation},
		},
		{
			name:      "a valid session is reused, read once for both questions",
			world:     authorizeWorld{emitted: true, sessionValid: true, userSubject: "sub-1", userEnabled: true},
			wantRoute: authorizeRouteSSO,
			wantReads: []authorizeFact{emission, session, validation, user},
		},
		{
			name:      "a withheld redirect reads the session only once the request is accepted",
			world:     authorizeWorld{emitted: false, sessionValid: true, userSubject: "sub-1", userEnabled: true},
			wantRoute: authorizeRouteSSO,
			wantReads: []authorizeFact{emission, validation, session, user},
		},
		{
			// UserSessionLoadUser is asked for a nil or invalid session too, and answers nil for none.
			name:      "no valid session goes to level 1, the session's user still loaded",
			world:     authorizeWorld{emitted: true, sessionValid: false},
			wantRoute: authorizeRouteLevel1,
			wantReads: []authorizeFact{emission, session, validation, user},
		},
		{
			name:      "no valid session goes to level 1 whatever the hint names",
			world:     authorizeWorld{emitted: true, sessionValid: false, hint: "sub-2", userSubject: "sub-1"},
			wantRoute: authorizeRouteLevel1,
			wantReads: []authorizeFact{emission, session, validation, user},
		},
		{
			name:      "a hint naming the session's user is reused",
			world:     authorizeWorld{emitted: true, sessionValid: true, hint: "sub-1", userSubject: "sub-1", userEnabled: true},
			wantRoute: authorizeRouteSSO,
			wantReads: []authorizeFact{emission, session, validation, user},
		},
		{
			// OIDC Core 3.1.2.1.
			name:      "a hint naming another user forces a login",
			world:     authorizeWorld{emitted: true, sessionValid: true, hint: "sub-2", userSubject: "sub-1", userEnabled: true},
			wantRoute: authorizeRouteForceLogin,
			wantReads: []authorizeFact{emission, session, validation, user},
		},
		{
			name:      "a hint naming another user is asked before the session's user is disabled",
			world:     authorizeWorld{emitted: true, sessionValid: true, hint: "sub-2", userSubject: "sub-1", userEnabled: false},
			wantRoute: authorizeRouteForceLogin,
			wantReads: []authorizeFact{emission, session, validation, user},
		},
		{
			name:      "a valid session whose user is disabled is refused",
			world:     authorizeWorld{emitted: true, sessionValid: true, hint: "sub-1", userSubject: "sub-1", userEnabled: false},
			wantRoute: authorizeRouteDisabledUser,
			wantReads: []authorizeFact{emission, session, validation, user},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			route, reads := driveAuthorizeRoute(t, tc.world)

			assert.Equal(t, tc.wantRoute, route)
			assert.Equal(t, tc.wantReads, reads)
		})
	}
}

// A refused request is answered now on exactly one of three clauses, and the clause that reads the
// session is reached only when the other two leave the answer open. Every combination, so no
// fourth clause and no dropped one passes (#213 decisions 4 and 8).
func TestDecideAuthorizeRoute_RefusalAnswersNowOnThreeClauses(t *testing.T) {
	for _, silent := range []bool{false, true} {
		for _, login := range []bool{false, true} {
			for _, emitted := range []bool{false, true} {
				for _, sessionValid := range []bool{false, true} {
					world := authorizeWorld{silent: silent, login: login, emitted: emitted,
						sessionValid: sessionValid, refused: true}

					route, _ := driveAuthorizeRoute(t, world)

					wantAnswerNow := silent || !emitted || (!login && sessionValid)
					if wantAnswerNow {
						assert.Equal(t, authorizeRouteAnswerNow, route, "%+v", world)
					} else {
						assert.Equal(t, authorizeRoutePark, route, "%+v", world)
					}
				}
			}
		}
	}
}

// The request's parameters are read from one url.Values, the query and a form body merged as
// r.FormValue merges them, the query's value first.
func TestAuthorizeParameters(t *testing.T) {
	t.Run("the query and the form body are one source", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/authorize?client_id=from-query&state=query-state",
			strings.NewReader("redirect_uri="+url.QueryEscape("https://example.com/cb")+"&state=body-state"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		params, err := authorizeParameters(req)
		require.NoError(t, err)

		assert.Equal(t, "from-query", params.Get("client_id"))
		assert.Equal(t, "https://example.com/cb", params.Get("redirect_uri"))
		assert.Equal(t, "body-state", params.Get("state"), "the body's value comes first, as r.FormValue answers")
		assert.Equal(t, req.FormValue("state"), params.Get("state"))
	})

	t.Run("a form already parsed is read as it stands", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=from-query", nil)
		req.Form = url.Values{"client_id": {"parsed-earlier"}}

		params, err := authorizeParameters(req)
		require.NoError(t, err)
		assert.Equal(t, "parsed-earlier", params.Get("client_id"))
	})

	t.Run("a multipart body is read, as r.FormValue reads it", func(t *testing.T) {
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		require.NoError(t, form.WriteField("state", "multipart-state"))
		require.NoError(t, form.Close())
		req := httptest.NewRequest(http.MethodPost, "/auth/authorize?client_id=from-query", &body)
		req.Header.Set("Content-Type", form.FormDataContentType())

		params, err := authorizeParameters(req)
		require.NoError(t, err)
		assert.Equal(t, "from-query", params.Get("client_id"))
		assert.Equal(t, "multipart-state", params.Get("state"))
	})

	// Until #228 a parse failure was ignored and the field holding it dropped, as r.FormValue does;
	// now it is returned, and HandleAuthorizeGet answers it on the refusal page.
	t.Run("a body that does not parse is an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/authorize?client_id=from-query",
			strings.NewReader("state=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := authorizeParameters(req)
		assert.Error(t, err)
	})

	t.Run("a query that does not parse is an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=from-query&state=%zz", nil)

		_, err := authorizeParameters(req)
		assert.Error(t, err)
	})

	t.Run("a multipart body that does not parse is an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/authorize", strings.NewReader("not a multipart body"))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=xyz")

		_, err := authorizeParameters(req)
		assert.Error(t, err)
	})
}

// The five validations run in order and the first refusal ends them; a validator's fault is
// returned rather than taken for a refusal; and the prompt, once accepted, is kept when the hint
// after it is refused, so a parked ceremony carries it as it always did. The handler cases show
// each validation's refusal reaching the client (#437 seam 4).
func TestValidateAuthorizeRequest(t *testing.T) {
	requestRefusal := oauth.NewErrorDetailWithHTTPStatus("invalid_request", "The request is invalid.", http.StatusBadRequest)

	testCases := []struct {
		name            string
		hint            string
		scope           string
		requestErr      error
		scopesErr       error
		wantRefusalCode string
		wantPrompt      string
		wantHint        string
		wantFault       bool
		wantCalls       []string
	}{
		{
			name:       "every validation accepts",
			wantPrompt: "login",
			wantCalls:  []string{"ValidateUnsupportedRequestParameters", "ValidateRequest", "ValidateScopes", "ValidatePrompt"},
		},
		{
			name:            "the first refusal ends the validations",
			requestErr:      requestRefusal,
			wantRefusalCode: "invalid_request",
			wantCalls:       []string{"ValidateUnsupportedRequestParameters", "ValidateRequest"},
		},
		{
			name:      "a validator's fault is returned, not refused",
			scopesErr: errors.New("the database is unavailable"),
			wantFault: true,
			wantCalls: []string{"ValidateUnsupportedRequestParameters", "ValidateRequest", "ValidateScopes"},
		},
		{
			// After the scopes, which establish that it exists, and before the prompt (#499).
			name:            "an administrative scope the client may not request is refused after the scopes",
			scope:           "openid authserver:manage",
			wantRefusalCode: "invalid_scope",
			wantCalls:       []string{"ValidateUnsupportedRequestParameters", "ValidateRequest", "ValidateScopes"},
		},
		{
			name:            "a refused hint keeps the accepted prompt",
			hint:            "not-a-token",
			wantRefusalCode: "invalid_request",
			wantPrompt:      "login",
			wantCalls:       []string{"ValidateUnsupportedRequestParameters", "ValidateRequest", "ValidateScopes", "ValidatePrompt", "DecodeAndValidateTokenString"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authorizeValidator := handlersmocks.NewAuthorizeValidator(t)
			tokenParser := handlersmocks.NewTokenParser(t)
			var calls []string
			recordCall := func(name string) func(mock.Arguments) {
				return func(mock.Arguments) { calls = append(calls, name) }
			}

			authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.Anything).
				Run(recordCall("ValidateUnsupportedRequestParameters")).Return(nil).Maybe()
			authorizeValidator.On("ValidateRequest", mock.Anything).
				Run(recordCall("ValidateRequest")).Return(tc.requestErr).Maybe()
			scope := "openid"
			if tc.scope != "" {
				scope = tc.scope
			}
			authorizeValidator.On("ValidateScopes", mock.Anything, scope).
				Run(recordCall("ValidateScopes")).Return(tc.scopesErr).Maybe()
			authorizeValidator.On("ValidatePrompt", "login").
				Run(recordCall("ValidatePrompt")).Return("login", nil).Maybe()
			tokenParser.On("DecodeAndValidateTokenString", mock.Anything, "not-a-token", false).
				Run(recordCall("DecodeAndValidateTokenString")).Return(nil, errors.New("malformed")).Maybe()

			// ValidateScopes is handed the scope as sent, never the request's normalized copy, whose
			// spaces would hide a malformed one (#244): the copy below differs, so a call with it
			// matches no expectation.
			params := url.Values{"prompt": {"login"}, "scope": {scope}}
			if tc.hint != "" {
				params.Set("id_token_hint", tc.hint)
			}

			// The administrative check reads the request's normalized copy, which here is the scope
			// as sent, so a row asking for an administrative scope is judged on it.
			normalized := "the normalized copy"
			if tc.scope != "" {
				normalized = tc.scope
			}
			validation, err := validateAuthorizeRequest(context.Background(), authorizeValidator, tokenParser,
				&record.Settings{Issuer: "https://test-issuer.com"}, &record.Client{ClientIdentifier: "test-client"}, params,
				&protocolvalidation.ValidateRequestInput{Scope: normalized})

			assert.Equal(t, tc.wantCalls, calls)
			if tc.wantFault {
				require.Error(t, err)
				assert.Nil(t, validation.refusal)
				return
			}
			require.NoError(t, err)
			if tc.wantRefusalCode == "" {
				assert.Nil(t, validation.refusal)
			} else {
				require.NotNil(t, validation.refusal)
				assert.Equal(t, tc.wantRefusalCode, validation.refusal.Code())
			}
			if tc.scope != "" {
				assert.Equal(t, []string{"authserver:manage"}, validation.refusedAdministrativeScopes)
			} else {
				assert.Nil(t, validation.refusedAdministrativeScopes)
			}
			assert.Equal(t, tc.wantPrompt, validation.prompt)
			assert.Equal(t, tc.wantHint, validation.hintSubject)
		})
	}
}
