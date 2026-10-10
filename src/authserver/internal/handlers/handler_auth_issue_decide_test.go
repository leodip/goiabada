package handlers

import (
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ceremonyGeneration is the authentication generation every ceremony below authenticated at, non-zero
// so a comparison against a defaulted field cannot pass by accident.
const ceremonyGeneration = 5

// issuanceWorld is what HandleIssueGet would load, answered from the row instead of from a
// database, so a decideIssuance case is a table row with no HTTP harness and no mocks.
type issuanceWorld struct {
	redirectURI  string
	responseType string
	hint         string
	registered   []string
	// identifier is whether the request resolved a session identifier.
	identifier bool
	// clientDisabled turns the client off, and implicitOff and codeOff switch the two flows off for it.
	clientDisabled bool
	implicitOff    bool
	codeOff        bool
	// administrativeRefused says the scope to be issued names an administrative scope the client may
	// no longer request, which is known with the registration (#499).
	administrativeRefused bool
	// userSubject is the ceremony user's subject; noUser makes the user missing; userDisabled disables
	// them; generationDrift is how far the user's authentication generation has moved from the one the
	// ceremony authenticated at, 0 for current.
	userSubject     string
	noUser          bool
	userDisabled    bool
	generationDrift int64
	// claimsOTP says the ceremony's methods name a one-time code, and noAuthenticator that the user
	// has none now; every other ceremony's user has one (#542 decision 1).
	claimsOTP       bool
	noAuthenticator bool
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
		authStateGeneration:      ceremonyGeneration,
		claimsOTP:                world.claimsOTP,
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
			facts.clientEnabled = !world.clientDisabled
			if world.administrativeRefused {
				facts.refusedAdministrativeScopes = []string{"authserver:manage"}
			}
		case issuanceFactFlows:
			facts.flows = &clientFlows{implicit: !world.implicitOff, code: !world.codeOff}
		case issuanceFactUser:
			facts.userLoaded = true
			if !world.noUser {
				facts.user = &record.User{
					Subject:             world.userSubject,
					Enabled:             !world.userDisabled,
					AuthStateGeneration: ceremonyGeneration + world.generationDrift,
					OTPEnabled:          !world.noAuthenticator,
				}
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
		flows        = issuanceFactFlows
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
			wantReads: []issuanceFact{registration, flows, session, validity, user, scope},
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
			wantReads: []issuanceFact{registration, flows, session, validity, user, scope},
		},
		{
			// IsCodeOnly: the parser reports the repeated token (#244). A ceremony stored before
			// ValidateRequest refused "code code" can still hold it, and must not buy the port.
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
			name: "an unrecognised token beside code buys no loopback port",
			world: with(func(w *issuanceWorld) {
				w.registered = []string{"http://127.0.0.1/callback"}
				w.redirectURI = "http://127.0.0.1:5555/callback"
				w.responseType = "code foo"
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

		// 2. The client, and the flow the ceremony is for (#197). Each reads only what it needs.
		{
			name:      "a client disabled since /auth/authorize is refused, reading nothing else",
			world:     with(func(w *issuanceWorld) { w.clientDisabled = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseClientDisabled},
			wantReads: []issuanceFact{registration},
		},
		{
			name: "a disabled client outranks a hint naming another user and a session that is gone",
			world: with(func(w *issuanceWorld) {
				w.clientDisabled = true
				w.hint = "subject-b"
				w.session = false
			}),
			want:      issuanceAnswer{outcome: issuanceRefuseClientDisabled},
			wantReads: []issuanceFact{registration},
		},
		{
			// The registration is what every later refusal that redirects leans on, so it stays first.
			name: "an unregistered redirect outranks a disabled client",
			world: with(func(w *issuanceWorld) {
				w.clientDisabled = true
				w.registered = []string{"https://app.example.com/other"}
			}),
			want:      issuanceAnswer{outcome: issuanceRefuseUnregisteredRedirect},
			wantReads: []issuanceFact{registration},
		},
		{
			name:      "the code flow switched off is refused for a code ceremony",
			world:     with(func(w *issuanceWorld) { w.codeOff = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseCodeDisabled},
			wantReads: []issuanceFact{registration, flows},
		},
		{
			name:      "the implicit grant switched off is refused for an implicit ceremony: token",
			world:     with(func(w *issuanceWorld) { w.responseType = "token"; w.implicitOff = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseImplicitDisabled},
			wantReads: []issuanceFact{registration, flows},
		},
		{
			name:      "the implicit grant switched off is refused for an implicit ceremony: id_token",
			world:     with(func(w *issuanceWorld) { w.responseType = "id_token"; w.implicitOff = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseImplicitDisabled},
			wantReads: []issuanceFact{registration, flows},
		},
		{
			name:      "the implicit grant switched off is refused for an implicit ceremony: id_token token",
			world:     with(func(w *issuanceWorld) { w.responseType = "id_token token"; w.implicitOff = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseImplicitDisabled},
			wantReads: []issuanceFact{registration, flows},
		},
		{
			// The leniency each flow keeps: one switch never refuses the other flow's ceremony.
			name:      "the implicit grant switched off does not refuse a code ceremony",
			world:     with(func(w *issuanceWorld) { w.implicitOff = true }),
			want:      issuanceAnswer{outcome: issuanceIssueCode},
			wantReads: []issuanceFact{registration, flows, session, validity, user, scope},
		},

		// 2, continued. An administrative scope the client may no longer request (#499 decision 6):
		// the allowance withdrawn while the ceremony sat on a step takes effect here. It is about the
		// client, so it sits with the client's checks and reads nothing past them.
		{
			name:      "an administrative scope the client may not request is refused, reading nothing past the flows",
			world:     with(func(w *issuanceWorld) { w.administrativeRefused = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseAdministrativeScope},
			wantReads: []issuanceFact{registration, flows},
		},
		{
			name:      "it is refused for an implicit ceremony too",
			world:     with(func(w *issuanceWorld) { w.administrativeRefused = true; w.responseType = "id_token token" }),
			want:      issuanceAnswer{outcome: issuanceRefuseAdministrativeScope},
			wantReads: []issuanceFact{registration, flows},
		},
		{
			name: "it outranks a hint naming another user and a session that is gone",
			world: with(func(w *issuanceWorld) {
				w.administrativeRefused = true
				w.hint = "subject-b"
				w.session = false
			}),
			want:      issuanceAnswer{outcome: issuanceRefuseAdministrativeScope},
			wantReads: []issuanceFact{registration, flows},
		},
		{
			name:      "a disabled client outranks it",
			world:     with(func(w *issuanceWorld) { w.administrativeRefused = true; w.clientDisabled = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseClientDisabled},
			wantReads: []issuanceFact{registration},
		},
		{
			name:      "the flow switched off outranks it",
			world:     with(func(w *issuanceWorld) { w.administrativeRefused = true; w.codeOff = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseCodeDisabled},
			wantReads: []issuanceFact{registration, flows},
		},
		{
			name:      "the code flow switched off does not refuse an implicit ceremony",
			world:     with(func(w *issuanceWorld) { w.responseType = "id_token token"; w.codeOff = true }),
			want:      issuanceAnswer{outcome: issuanceIssueImplicit},
			wantReads: []issuanceFact{registration, flows, session, validity, user, scope},
		},
		{
			name: "a flow switched off outranks a hint naming another user and a session that is gone",
			world: with(func(w *issuanceWorld) {
				w.codeOff = true
				w.hint = "subject-b"
				w.session = false
			}),
			want:      issuanceAnswer{outcome: issuanceRefuseCodeDisabled},
			wantReads: []issuanceFact{registration, flows},
		},
		{
			name:      "a disabled client outranks a flow switched off",
			world:     with(func(w *issuanceWorld) { w.clientDisabled = true; w.codeOff = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseClientDisabled},
			wantReads: []issuanceFact{registration},
		},

		// 3. The id_token_hint (OIDC Core 3.1.2.2).
		{
			name:      "a hint naming another user is refused before the session is read",
			world:     with(func(w *issuanceWorld) { w.hint = "subject-b" }),
			want:      issuanceAnswer{outcome: issuanceRefuseHintMismatch},
			wantReads: []issuanceFact{registration, flows, user},
		},
		{
			name:      "a hint whose user no longer exists is refused as a mismatch, not a 500",
			world:     with(func(w *issuanceWorld) { w.hint = "subject-a"; w.noUser = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseHintMismatch},
			wantReads: []issuanceFact{registration, flows, user},
		},
		{
			name:      "a matching hint reads the user once, first",
			world:     with(func(w *issuanceWorld) { w.hint = "subject-a" }),
			want:      issuanceAnswer{outcome: issuanceIssueCode},
			wantReads: []issuanceFact{registration, flows, user, session, validity, scope},
		},

		// 4. The session (#129, #133, #241).
		{
			name:      "no identifier on a code ceremony is the gone shape, without a session read",
			world:     with(func(w *issuanceWorld) { w.identifier = false; w.session = false }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGone},
			wantReads: []issuanceFact{registration, flows, validity},
		},
		{
			name:      "an identifier whose row is gone is the gone shape",
			world:     with(func(w *issuanceWorld) { w.session = false }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGone},
			wantReads: []issuanceFact{registration, flows, session, validity},
		},
		{
			name:      "another user's session is the foreign shape",
			world:     with(func(w *issuanceWorld) { w.owned = false }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionForeign},
			wantReads: []issuanceFact{registration, flows, session, validity},
		},
		{
			name:      "another user's expired session is foreign before it is expired",
			world:     with(func(w *issuanceWorld) { w.owned = false; w.valid = false }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionForeign},
			wantReads: []issuanceFact{registration, flows, session, validity},
		},
		{
			name:      "an owned session out of time is the expired shape",
			world:     with(func(w *issuanceWorld) { w.valid = false }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionExpired},
			wantReads: []issuanceFact{registration, flows, session, validity},
		},
		{
			// The exemption #133 made and #197 took away (decision 16): the tokens of an implicit
			// ceremony with no session name no session that a termination could ever end, and the
			// code flow already refuses the same ceremony.
			name: "an implicit ceremony with no identifier is the gone shape, as a code ceremony's is",
			world: with(func(w *issuanceWorld) {
				w.responseType = "id_token token"
				w.identifier = false
				w.session = false
			}),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGone},
			wantReads: []issuanceFact{registration, flows, validity},
		},
		{
			name: "an implicit ceremony bound to another user's session is refused as foreign",
			world: with(func(w *issuanceWorld) {
				w.responseType = "token"
				w.owned = false
			}),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionForeign},
			wantReads: []issuanceFact{registration, flows, session, validity},
		},
		{
			name: "an implicit ceremony whose identifier's row is gone is refused as gone",
			world: with(func(w *issuanceWorld) {
				w.responseType = "id_token"
				w.session = false
			}),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGone},
			wantReads: []issuanceFact{registration, flows, session, validity},
		},

		// 5. The user, and the credential the ceremony authenticated with (#197).
		{
			name:      "a user gone since /auth/completed answers the 500",
			world:     with(func(w *issuanceWorld) { w.noUser = true }),
			want:      issuanceAnswer{outcome: issuanceUserMissing},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},
		{
			name:      "a user disabled since /auth/completed is refused as access_denied",
			world:     with(func(w *issuanceWorld) { w.userDisabled = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseUserDisabled},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},
		{
			name:      "a disabled user of an implicit ceremony is refused too",
			world:     with(func(w *issuanceWorld) { w.responseType = "token"; w.userDisabled = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseUserDisabled},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},
		{
			// The session is what a ceremony about to be restarted pays nothing past.
			name:      "a session that is gone outranks a disabled user, whom it never reads",
			world:     with(func(w *issuanceWorld) { w.session = false; w.userDisabled = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGone},
			wantReads: []issuanceFact{registration, flows, session, validity},
		},
		{
			name:      "a matching hint on a disabled user is read once and refused after the session",
			world:     with(func(w *issuanceWorld) { w.hint = "subject-a"; w.userDisabled = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseUserDisabled},
			wantReads: []issuanceFact{registration, flows, user, session, validity},
		},
		{
			// The user's generation has moved on: a password change or a revocation since the
			// ceremony authenticated. The token endpoint would refuse the code (#106, #197).
			name:      "a user whose generation moved on since the ceremony authenticated restarts it",
			world:     with(func(w *issuanceWorld) { w.generationDrift = 1 }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGenerationStale},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},
		{
			name:      "a generation several steps on is refused as well",
			world:     with(func(w *issuanceWorld) { w.generationDrift = 4 }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGenerationStale},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},
		{
			// Only a current generation issues, the token endpoint's own comparison: a ceremony
			// claiming a generation the user has not reached is no more current than a stale one.
			name:      "a ceremony ahead of the user's generation is refused as well",
			world:     with(func(w *issuanceWorld) { w.generationDrift = -1 }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGenerationStale},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},
		{
			name:      "an implicit ceremony with a stale generation restarts too",
			world:     with(func(w *issuanceWorld) { w.responseType = "id_token token"; w.generationDrift = 1 }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGenerationStale},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},
		{
			name:      "a disabled user outranks a stale generation",
			world:     with(func(w *issuanceWorld) { w.userDisabled = true; w.generationDrift = 1 }),
			want:      issuanceAnswer{outcome: issuanceRefuseUserDisabled},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},
		{
			// The authenticator was removed while the ceremony sat on a step (#542 decision 1).
			name:      "a ceremony naming a code for a user with no authenticator restarts",
			world:     with(func(w *issuanceWorld) { w.claimsOTP = true; w.noAuthenticator = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionAuthenticatorRemoved},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},
		{
			name:      "an implicit ceremony naming a removed authenticator restarts too",
			world:     with(func(w *issuanceWorld) { w.responseType = "id_token"; w.claimsOTP = true; w.noAuthenticator = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionAuthenticatorRemoved},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},
		{
			name:      "a ceremony naming a code for a user who has an authenticator issues",
			world:     with(func(w *issuanceWorld) { w.claimsOTP = true }),
			want:      issuanceAnswer{outcome: issuanceIssueCode},
			wantReads: []issuanceFact{registration, flows, session, validity, user, scope},
		},
		{
			name:      "a ceremony naming no code issues for a user with no authenticator",
			world:     with(func(w *issuanceWorld) { w.noAuthenticator = true }),
			want:      issuanceAnswer{outcome: issuanceIssueCode},
			wantReads: []issuanceFact{registration, flows, session, validity, user, scope},
		},
		{
			name:      "a stale generation is named before a removed authenticator",
			world:     with(func(w *issuanceWorld) { w.generationDrift = 1; w.claimsOTP = true; w.noAuthenticator = true }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGenerationStale},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},
		{
			name:      "a stale generation outranks a scope the user no longer holds, which it never reads",
			world:     with(func(w *issuanceWorld) { w.generationDrift = 1; w.scope = "" }),
			want:      issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGenerationStale},
			wantReads: []issuanceFact{registration, flows, session, validity, user},
		},

		// 6. The live scope (#241).
		{
			name:      "a user holding none of the scopes is refused",
			world:     with(func(w *issuanceWorld) { w.scope = "" }),
			want:      issuanceAnswer{outcome: issuanceRefuseScopeDenied},
			wantReads: []issuanceFact{registration, flows, session, validity, user, scope},
		},
		{
			name:      "an implicit ceremony that passes every check issues tokens",
			world:     with(func(w *issuanceWorld) { w.responseType = "id_token token" }),
			want:      issuanceAnswer{outcome: issuanceIssueImplicit},
			wantReads: []issuanceFact{registration, flows, session, validity, user, scope},
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
