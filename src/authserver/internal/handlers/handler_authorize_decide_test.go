package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
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

		params := authorizeParameters(req)

		assert.Equal(t, "from-query", params.Get("client_id"))
		assert.Equal(t, "https://example.com/cb", params.Get("redirect_uri"))
		assert.Equal(t, "body-state", params.Get("state"), "the body's value comes first, as r.FormValue answers")
		assert.Equal(t, req.FormValue("state"), params.Get("state"))
	})

	t.Run("a form already parsed is read as it stands", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=from-query", nil)
		req.Form = url.Values{"client_id": {"parsed-earlier"}}

		assert.Equal(t, "parsed-earlier", authorizeParameters(req).Get("client_id"))
	})

	t.Run("a body that does not parse leaves the query, as r.FormValue does", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/authorize?client_id=from-query",
			strings.NewReader("state=%zz"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		params := authorizeParameters(req)

		assert.Equal(t, "from-query", params.Get("client_id"))
		assert.Equal(t, "", params.Get("state"))
	})
}

// The five validations run in order and the first refusal ends them; a validator's fault is
// returned rather than taken for a refusal; and the prompt, once accepted, is kept when the hint
// after it is refused, so a parked ceremony carries it as it always did. The handler cases show
// each validation's refusal reaching the client (#437 seam 4).
func TestValidateAuthorizeRequest(t *testing.T) {
	requestRefusal := customerrors.NewErrorDetailWithHttpStatusCode("invalid_request", "The request is invalid.", http.StatusBadRequest)

	testCases := []struct {
		name            string
		hint            string
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
			name:            "a refused hint keeps the accepted prompt",
			hint:            "not-a-token",
			wantRefusalCode: "invalid_request",
			wantPrompt:      "login",
			wantCalls:       []string{"ValidateUnsupportedRequestParameters", "ValidateRequest", "ValidateScopes", "ValidatePrompt", "DecodeAndValidateTokenString"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authorizeValidator := mocks_handlers.NewAuthorizeValidator(t)
			tokenParser := mocks_handlers.NewTokenParser(t)
			var calls []string
			record := func(name string) func(mock.Arguments) {
				return func(mock.Arguments) { calls = append(calls, name) }
			}

			authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.Anything).
				Run(record("ValidateUnsupportedRequestParameters")).Return(nil).Maybe()
			authorizeValidator.On("ValidateRequest", mock.Anything).
				Run(record("ValidateRequest")).Return(tc.requestErr).Maybe()
			authorizeValidator.On("ValidateScopes", mock.Anything, "openid").
				Run(record("ValidateScopes")).Return(tc.scopesErr).Maybe()
			authorizeValidator.On("ValidatePrompt", "login").
				Run(record("ValidatePrompt")).Return("login", nil).Maybe()
			tokenParser.On("DecodeAndValidateTokenString", mock.Anything, "not-a-token", false).
				Run(record("DecodeAndValidateTokenString")).Return(nil, errors.New("malformed")).Maybe()

			params := url.Values{"prompt": {"login"}}
			if tc.hint != "" {
				params.Set("id_token_hint", tc.hint)
			}

			validation, err := validateAuthorizeRequest(context.Background(), authorizeValidator, tokenParser,
				&models.Settings{Issuer: "https://test-issuer.com"}, params,
				&protocolvalidation.ValidateRequestInput{Scope: "openid"})

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
				assert.Equal(t, tc.wantRefusalCode, validation.refusal.GetCode())
			}
			assert.Equal(t, tc.wantPrompt, validation.prompt)
			assert.Equal(t, tc.wantHint, validation.hintSubject)
		})
	}
}

// silentWorld is what handlePromptNone would load for a prompt=none request, answered from the
// row, so a decideSilentAuthentication case needs no HTTP harness and no mocks.
type silentWorld struct {
	noSession          bool
	valid              bool
	maxAgeRequested    bool
	validWithoutMaxAge bool
	disabled           bool
	subject            string
	hint               string
	target             models.AcrLevel
	sessionAcr         models.AcrLevel
	sessionOtpGen      int64
	userOtpGen         int64
	otpEnabled         bool
	effectiveScope     string
	consentRequired    bool
	consentScope       *string // nil for no consent row
}

// driveSilentAuthentication runs decideSilentAuthentication as handlePromptNone does, loading each
// fact it asks for from the world, and answers the answer and the facts in the order asked for.
func driveSilentAuthentication(t *testing.T, world silentWorld) (silentAuthenticationAnswer, []silentFact) {
	t.Helper()

	facts := silentAuthenticationFacts{
		maxAgeRequested: world.maxAgeRequested,
		hintSubject:     world.hint,
		target:          world.target,
		consentRequired: world.consentRequired,
	}
	var asked []silentFact
	for {
		answer, need := decideSilentAuthentication(facts)
		if need == silentFactNone {
			return answer, asked
		}
		require.NotContains(t, asked, need, "each fact is loaded once")
		asked = append(asked, need)

		switch need {
		case silentFactSession:
			facts.sessionLoaded = true
			if !world.noSession {
				facts.session = &models.UserSession{
					UserId:              7,
					AcrLevel:            world.sessionAcr,
					OtpConfigGeneration: world.sessionOtpGen,
					User: models.User{
						Id:                  7,
						Subject:             world.subject,
						Enabled:             !world.disabled,
						OTPEnabled:          world.otpEnabled,
						OtpConfigGeneration: world.userOtpGen,
					},
				}
			}
		case silentFactValidity:
			valid := world.valid
			facts.sessionValid = &valid
		case silentFactValidityWithoutMaxAge:
			valid := world.validWithoutMaxAge
			facts.sessionValidWithoutMaxAge = &valid
		case silentFactEffectiveScope:
			scope := world.effectiveScope
			facts.effectiveScope = &scope
		case silentFactConsent:
			facts.consentLoaded = true
			if world.consentScope != nil {
				facts.consent = &models.UserConsent{UserId: 7, Scope: *world.consentScope}
			}
		default:
			require.FailNow(t, "an unknown fact", "%v", need)
		}
	}
}

// Every answer prompt=none can get, in the order the checks are asked, with the reads each makes:
// a refusal reads nothing past the check that refused. handlePromptNone's handler cases show each
// kind of answer reaching the client; which answer, and its exact text, is decided here (#437
// seam 1).
func TestDecideSilentAuthentication(t *testing.T) {
	const (
		session       = silentFactSession
		validity      = silentFactValidity
		withoutMaxAge = silentFactValidityWithoutMaxAge
		scope         = silentFactEffectiveScope
		consent       = silentFactConsent
	)
	scopes := func(s string) *string { return &s }

	// A session that passes every check before the scope, at level 1 for a level 1 target.
	passing := silentWorld{
		valid:          true,
		subject:        "sub-1",
		target:         models.AcrLevel1,
		sessionAcr:     models.AcrLevel1,
		effectiveScope: "openid profile",
	}
	with := func(edit func(*silentWorld)) silentWorld {
		world := passing
		edit(&world)
		return world
	}

	testCases := []struct {
		name             string
		world            silentWorld
		wantCode         string
		wantDescription  string
		wantUserDisabled bool
		wantReads        []silentFact
	}{
		{
			name:            "no session",
			world:           with(func(w *silentWorld) { w.noSession = true }),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "User authentication is required",
			wantReads:       []silentFact{session},
		},
		{
			name:            "an expired session with no max_age is not asked about max_age",
			world:           with(func(w *silentWorld) { w.valid = false; w.validWithoutMaxAge = true }),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "User session has expired",
			wantReads:       []silentFact{session, validity},
		},
		{
			name: "a session valid but for max_age says so",
			world: with(func(w *silentWorld) {
				w.valid = false
				w.maxAgeRequested = true
				w.validWithoutMaxAge = true
			}),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "Session age exceeds max_age",
			wantReads:       []silentFact{session, validity, withoutMaxAge},
		},
		{
			name: "a session expired with max_age as well is expired",
			world: with(func(w *silentWorld) {
				w.valid = false
				w.maxAgeRequested = true
				w.validWithoutMaxAge = false
			}),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "User session has expired",
			wantReads:       []silentFact{session, validity, withoutMaxAge},
		},
		{
			name: "a valid session with max_age asks nothing more about it",
			world: with(func(w *silentWorld) {
				w.maxAgeRequested = true
			}),
			wantReads: []silentFact{session, validity, scope},
		},
		{
			name:             "a disabled user, audited",
			world:            with(func(w *silentWorld) { w.disabled = true }),
			wantCode:         "access_denied",
			wantDescription:  "The user account is disabled",
			wantUserDisabled: true,
			wantReads:        []silentFact{session, validity},
		},
		{
			name:             "a disabled user is asked before the hint",
			world:            with(func(w *silentWorld) { w.disabled = true; w.hint = "sub-2" }),
			wantCode:         "access_denied",
			wantDescription:  "The user account is disabled",
			wantUserDisabled: true,
			wantReads:        []silentFact{session, validity},
		},
		{
			name:            "a hint naming another user",
			world:           with(func(w *silentWorld) { w.hint = "sub-2" }),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "The current session user does not match the id_token_hint",
			wantReads:       []silentFact{session, validity},
		},
		{
			name:      "a hint naming the session's user passes",
			world:     with(func(w *silentWorld) { w.hint = "sub-1" }),
			wantReads: []silentFact{session, validity, scope},
		},
		{
			name:            "a hint mismatch is asked before the step-up rule",
			world:           with(func(w *silentWorld) { w.hint = "sub-2"; w.target = models.AcrLevel2Mandatory }),
			wantCode:        oidc.ErrorLoginRequired,
			wantDescription: "The current session user does not match the id_token_hint",
			wantReads:       []silentFact{session, validity},
		},
		{
			name:            "a target above the session's level",
			world:           with(func(w *silentWorld) { w.target = models.AcrLevel2Optional; w.otpEnabled = true }),
			wantCode:        oidc.ErrorInteractionRequired,
			wantDescription: "Higher authentication level required",
			wantReads:       []silentFact{session, validity},
		},
		{
			name:            "an unknown session level is insufficient",
			world:           with(func(w *silentWorld) { w.sessionAcr = "urn:goiabada:pwd" }),
			wantCode:        oidc.ErrorInteractionRequired,
			wantDescription: "Higher authentication level required",
			wantReads:       []silentFact{session, validity},
		},
		{
			name: "a mandatory target with no authenticator, before the changed configuration",
			world: with(func(w *silentWorld) {
				w.target = models.AcrLevel2Mandatory
				w.sessionAcr = models.AcrLevel2Mandatory
				w.sessionOtpGen, w.userOtpGen = 2, 3
			}),
			wantCode:        oidc.ErrorInteractionRequired,
			wantDescription: "Additional authentication setup required",
			wantReads:       []silentFact{session, validity},
		},
		{
			name: "the authenticator changed since the session answered level 2",
			world: with(func(w *silentWorld) {
				w.target = models.AcrLevel2Optional
				w.sessionAcr = models.AcrLevel2Optional
				w.otpEnabled = true
				w.sessionOtpGen, w.userOtpGen = 2, 3
			}),
			wantCode:        oidc.ErrorInteractionRequired,
			wantDescription: "Authentication configuration has changed",
			wantReads:       []silentFact{session, validity},
		},
		{
			// The level 2 question is not asked of a level 1 target.
			name: "a changed authenticator does not refuse a level 1 target",
			world: with(func(w *silentWorld) {
				w.sessionAcr = models.AcrLevel2Optional
				w.sessionOtpGen, w.userOtpGen = 2, 3
			}),
			wantReads: []silentFact{session, validity, scope},
		},
		{
			name: "a mandatory target satisfied by an enrolled session passes",
			world: with(func(w *silentWorld) {
				w.target = models.AcrLevel2Mandatory
				w.sessionAcr = models.AcrLevel2Mandatory
				w.otpEnabled = true
			}),
			wantReads: []silentFact{session, validity, scope},
		},
		{
			name:            "no requested scope the user holds",
			world:           with(func(w *silentWorld) { w.effectiveScope = "  " }),
			wantCode:        "access_denied",
			wantDescription: "The user is not authorized to access any of the requested scopes",
			wantReads:       []silentFact{session, validity, scope},
		},
		{
			name:      "no consent asked for when the client does not require it and offline_access is absent",
			world:     passing,
			wantReads: []silentFact{session, validity, scope},
		},
		{
			name:            "a client requiring consent with none given",
			world:           with(func(w *silentWorld) { w.consentRequired = true }),
			wantCode:        oidc.ErrorConsentRequired,
			wantDescription: "User consent is required",
			wantReads:       []silentFact{session, validity, scope, consent},
		},
		{
			name: "a consent missing one scope",
			world: with(func(w *silentWorld) {
				w.consentRequired = true
				w.consentScope = scopes("openid")
			}),
			wantCode:        oidc.ErrorConsentRequired,
			wantDescription: "Additional consent is required",
			wantReads:       []silentFact{session, validity, scope, consent},
		},
		{
			name: "a consent covering every scope passes",
			world: with(func(w *silentWorld) {
				w.consentRequired = true
				w.consentScope = scopes("openid profile email")
			}),
			wantReads: []silentFact{session, validity, scope, consent},
		},
		{
			name: "offline_access asks for consent on a client that does not require it",
			world: with(func(w *silentWorld) {
				w.effectiveScope = "openid offline_access"
				w.consentScope = scopes("openid")
			}),
			wantCode:        oidc.ErrorConsentRequired,
			wantDescription: "Additional consent is required",
			wantReads:       []silentFact{session, validity, scope, consent},
		},
		{
			name: "offline_access covered by the consent passes",
			world: with(func(w *silentWorld) {
				w.effectiveScope = "openid offline_access"
				w.consentScope = scopes("openid offline_access")
			}),
			wantReads: []silentFact{session, validity, scope, consent},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			answer, reads := driveSilentAuthentication(t, tc.world)

			assert.Equal(t, tc.wantCode, answer.errorCode)
			assert.Equal(t, tc.wantDescription, answer.errorDescription)
			assert.Equal(t, tc.wantUserDisabled, answer.userDisabled)
			assert.Equal(t, tc.wantReads, reads)
		})
	}
}
