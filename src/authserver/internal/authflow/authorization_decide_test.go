package authflow

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authorizeWorld is what Authorization.Run would load, answered from the row instead of from a
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

// driveAuthorizeRoute runs decideAuthorizeRoute as Authorization.Run does, loading each fact it
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
