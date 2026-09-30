package handlers

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// issuanceWorld is what HandleIssueGet would load, answered from the row instead of from a
// database, so a decideIssuance case is a table row with no HTTP harness and no mocks.
type issuanceWorld struct {
	redirectURI  string
	responseType string
	hint         string
	registered   []string
	// identifier is whether the request resolved a session identifier.
	identifier bool
	// userSubject is the ceremony user's subject; noUser makes the user missing.
	userSubject string
	noUser      bool
	// session is whether the identifier names a row; owned and valid are about that row, and valid
	// is also HasValidUserSession's answer for no row, which is false.
	session bool
	owned   bool
	valid   bool
	scope   string
}

// driveIssuance runs decideIssuance as HandleIssueGet does, loading each fact it asks for from the
// world, and answers the answer and the facts in the order they were asked for.
func driveIssuance(t *testing.T, world issuanceWorld) (issuanceAnswer, []issuanceFact) {
	t.Helper()

	facts := issuanceFacts{
		redirectURI:              world.redirectURI,
		responseType:             world.responseType,
		hintSubject:              world.hint,
		sessionIdentifierPresent: world.identifier,
	}
	var asked []issuanceFact
	for {
		answer, need := decideIssuance(facts)
		if need == issuanceFactNone {
			require.NotEqual(t, issuanceUndecided, answer.outcome, "a decided ceremony has an outcome")
			return answer, asked
		}
		require.NotContains(t, asked, need, "each fact is loaded once")
		asked = append(asked, need)

		switch need {
		case issuanceFactRegistration:
			facts.registrationLoaded = true
			facts.registeredRedirectURIs = world.registered
		case issuanceFactUser:
			facts.userLoaded = true
			if !world.noUser {
				facts.user = &models.User{Subject: world.userSubject}
			}
		case issuanceFactSession:
			require.True(t, world.identifier, "the session is read only for a resolved identifier")
			facts.sessionLoaded = true
			facts.sessionPresent = world.session
			facts.sessionOwned = world.session && world.owned
		case issuanceFactSessionValidity:
			valid := world.session && world.valid
			facts.sessionValid = &valid
		case issuanceFactEffectiveScope:
			scope := world.scope
			facts.effectiveScope = &scope
		default:
			require.FailNow(t, "an unknown fact", "%v", need)
		}
	}
}

// Every outcome /auth/issue can reach, and the reads each makes. The handler cases show each
// outcome reaching its act; which outcome a ceremony reaches, and what it reads on the way, is
// decided here (#437 seam 1). The reads are part of the answer: an unregistered redirect reads
// nothing else, the user is read for a hint before the session, the session only for a resolved
// identifier, and a ceremony about to be restarted never pays for the scope filter (#129, #133,
// #241).
func TestDecideIssuance(t *testing.T) {
	const (
		registration = issuanceFactRegistration
		user         = issuanceFactUser
		session      = issuanceFactSession
		validity     = issuanceFactSessionValidity
		scope        = issuanceFactEffectiveScope
	)
	const callback = "https://app.example.com/callback"

	// ok is a code ceremony that issues; each case varies one thing from it.
	ok := issuanceWorld{
		redirectURI: callback, responseType: "code", registered: []string{callback},
		identifier: true, userSubject: "subject-a", session: true, owned: true, valid: true, scope: "openid",
	}
	with := func(edit func(w *issuanceWorld)) issuanceWorld {
		w := ok
		w.registered = append([]string(nil), ok.registered...)
		edit(&w)
		return w
	}

	testCases := []struct {
		name      string
		world     issuanceWorld
		want      issuanceAnswer
		wantReads []issuanceFact
	}{
		{
			name:      "a ceremony that passes every check issues a code",
			world:     ok,
			want:      issuanceAnswer{outcome: issuanceIssueCode},
			wantReads: []issuanceFact{registration, session, validity, user, scope},
		},

		// 1. The registration (#241).
		{
			name:      "a redirect URI no longer registered is refused, reading nothing else",
			world:     with(func(w *issuanceWorld) { w.registered = []string{"https://app.example.com/other"} }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnregisteredRedirect},
			wantReads: []issuanceFact{registration},
		},
		{
			name:      "a missing client has no registrations and is refused",
			world:     with(func(w *issuanceWorld) { w.registered = []string{} }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnregisteredRedirect},
			wantReads: []issuanceFact{registration},
		},
		{
			// RFC 8252 7.3: a loopback redirect may name any port, for a lone code response type.
			name: "a loopback redirect on another port is registered for response_type=code",
			world: with(func(w *issuanceWorld) {
				w.registered = []string{"http://127.0.0.1/callback"}
				w.redirectURI = "http://127.0.0.1:5555/callback"
			}),
			want:      issuanceAnswer{outcome: issuanceIssueCode},
			wantReads: []issuanceFact{registration, session, validity, user, scope},
		},
		{
			// The token sequence, not ParseResponseType's collapsed booleans.
			name: "a repeated code token buys no loopback port",
			world: with(func(w *issuanceWorld) {
				w.registered = []string{"http://127.0.0.1/callback"}
				w.redirectURI = "http://127.0.0.1:5555/callback"
				w.responseType = "code code"
			}),
			want:      issuanceAnswer{outcome: issuanceRefuseUnregisteredRedirect},
			wantReads: []issuanceFact{registration},
		},
		{
			name: "an implicit response type buys no loopback port",
			world: with(func(w *issuanceWorld) {
				w.registered = []string{"http://127.0.0.1/callback"}
				w.redirectURI = "http://127.0.0.1:5555/callback"
				w.responseType = "id_token"
			}),
			want:      issuanceAnswer{outcome: issuanceRefuseUnregisteredRedirect},
			wantReads: []issuanceFact{registration},
		},

		// 2. The id_token_hint (OIDC Core 3.1.2.2).
		{
			name:      "a hint naming another user is refused before the session is read",
			world:     with(func(w *issuanceWorld) { w.hint = "subject-b" }),
			want:      issuanceAnswer{outcome: issuanceRefuseHintMismatch},
			wantReads: []issuanceFact{registration, user},
		},
		{
			name:      "a hint whose user no longer exists is refused as a mismatch, not a 500",
			world:     with(func(w *issuanceWorld) { w.hint = "subject-a"; w.noUser = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseHintMismatch},
			wantReads: []issuanceFact{registration, user},
		},
		{
			name:      "a matching hint reads the user once, first",
			world:     with(func(w *issuanceWorld) { w.hint = "subject-a" }),
			want:      issuanceAnswer{outcome: issuanceIssueCode},
			wantReads: []issuanceFact{registration, user, session, validity, scope},
		},

		// 3. The session (#129, #133, #241).
		{
			name:      "no identifier on a code ceremony is the gone shape, without a session read",
			world:     with(func(w *issuanceWorld) { w.identifier = false; w.session = false }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGone},
			wantReads: []issuanceFact{registration, validity},
		},
		{
			name:      "an identifier whose row is gone is the gone shape",
			world:     with(func(w *issuanceWorld) { w.session = false }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGone},
			wantReads: []issuanceFact{registration, session, validity},
		},
		{
			name:      "another user's session is the foreign shape",
			world:     with(func(w *issuanceWorld) { w.owned = false }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionForeign},
			wantReads: []issuanceFact{registration, session, validity},
		},
		{
			name:      "another user's expired session is foreign before it is expired",
			world:     with(func(w *issuanceWorld) { w.owned = false; w.valid = false }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionForeign},
			wantReads: []issuanceFact{registration, session, validity},
		},
		{
			name:      "an owned session out of time is the expired shape",
			world:     with(func(w *issuanceWorld) { w.valid = false }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionExpired},
			wantReads: []issuanceFact{registration, session, validity},
		},
		{
			// Nothing to cross-bind to, and no refresh token to outlive a session (#133).
			name: "an implicit ceremony with no identifier is exempt and issues tokens",
			world: with(func(w *issuanceWorld) {
				w.responseType = "id_token token"
				w.identifier = false
				w.session = false
			}),
			want:      issuanceAnswer{outcome: issuanceIssueImplicit},
			wantReads: []issuanceFact{registration, validity, user, scope},
		},
		{
			name: "an implicit ceremony bound to another user's session is refused as foreign",
			world: with(func(w *issuanceWorld) {
				w.responseType = "token"
				w.owned = false
			}),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionForeign},
			wantReads: []issuanceFact{registration, session, validity},
		},
		{
			name: "an implicit ceremony whose identifier's row is gone is refused as gone",
			world: with(func(w *issuanceWorld) {
				w.responseType = "id_token"
				w.session = false
			}),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGone},
			wantReads: []issuanceFact{registration, session, validity},
		},

		// 4. The user.
		{
			name:      "a user gone since /auth/completed answers the 500",
			world:     with(func(w *issuanceWorld) { w.noUser = true }),
			want:      issuanceAnswer{outcome: issuanceUserMissing},
			wantReads: []issuanceFact{registration, session, validity, user},
		},

		// 5. The live scope (#241).
		{
			name:      "a user holding none of the scopes is refused",
			world:     with(func(w *issuanceWorld) { w.scope = "" }),
			want:      issuanceAnswer{outcome: issuanceRefuseScopeDenied},
			wantReads: []issuanceFact{registration, session, validity, user, scope},
		},
		{
			name:      "an implicit ceremony that passes every check issues tokens",
			world:     with(func(w *issuanceWorld) { w.responseType = "id_token token" }),
			want:      issuanceAnswer{outcome: issuanceIssueImplicit},
			wantReads: []issuanceFact{registration, session, validity, user, scope},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			answer, reads := driveIssuance(t, tc.world)
			assert.Equal(t, tc.want, answer)
			assert.Equal(t, tc.wantReads, reads)
		})
	}
}
