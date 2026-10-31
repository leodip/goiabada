package authflow

import (
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/urlmatch"
	"github.com/leodip/goiabada/core/loopback"
)

// issuanceFact is a fact decideIssuance needs and has not been given. Issuance.Run loads it and asks
// again.
type issuanceFact int

const (
	// issuanceFactNone means the answer is decided.
	issuanceFactNone issuanceFact = iota
	// issuanceFactRegistration is the client's registered redirect URIs, none for a missing client, and
	// whether it is enabled.
	issuanceFactRegistration
	// issuanceFactFlows is which authorization flows the client may use.
	issuanceFactFlows
	// issuanceFactUser is the ceremony's user, or none.
	issuanceFactUser
	// issuanceFactSession is the session the request's identifier names, or none.
	issuanceFactSession
	// issuanceFactSessionValidity is whether that session is valid, max_age not applied.
	issuanceFactSessionValidity
	// issuanceFactEffectiveScope is the scope to be issued narrowed to what the user holds.
	issuanceFactEffectiveScope
)

// issuanceOutcome is what /auth/issue does with a ceremony.
type issuanceOutcome int

const (
	// issuanceUndecided is returned beside a fact still to load.
	issuanceUndecided issuanceOutcome = iota
	// issuanceRefuseUnregisteredRedirect renders the refusal page: the redirect URI is no longer
	// registered on the client.
	issuanceRefuseUnregisteredRedirect
	// issuanceRefuseInsecureRedirect renders the same refusal page: the redirect URI is plain http
	// off the loopback interface, registered before intake refused the shape.
	issuanceRefuseInsecureRedirect
	// issuanceRefuseClientDisabled renders the refusal page /auth/authorize renders for a disabled client.
	issuanceRefuseClientDisabled
	// issuanceRefuseImplicitDisabled answers unauthorized_client: the ceremony is an implicit one and the
	// client may no longer use the implicit grant.
	issuanceRefuseImplicitDisabled
	// issuanceRefuseCodeDisabled answers unauthorized_client: the ceremony is a code one and the client
	// may no longer use the authorization code flow.
	issuanceRefuseCodeDisabled
	// issuanceRefuseAdministrativeScope answers invalid_scope: the scope to be issued names an
	// administrative scope the client may no longer request.
	issuanceRefuseAdministrativeScope
	// issuanceRefuseHintMismatch answers login_required: the user is not the id_token_hint's.
	issuanceRefuseHintMismatch
	// issuanceRefuseUnusableSession is refuseUnusableSession, for sessionShape.
	issuanceRefuseUnusableSession
	// issuanceUserMissing answers 500: the ceremony's user no longer exists.
	issuanceUserMissing
	// issuanceRefuseUserDisabled answers access_denied: the ceremony's user has been disabled.
	issuanceRefuseUserDisabled
	// issuanceRefuseScopeDenied answers access_denied: the user holds none of the scopes.
	issuanceRefuseScopeDenied
	// issuanceIssueImplicit issues tokens for an implicit response type.
	issuanceIssueImplicit
	// issuanceIssueCode issues an authorization code.
	issuanceIssueCode
)

// issuanceAnswer is decideIssuance's answer.
type issuanceAnswer struct {
	outcome issuanceOutcome
	// sessionShape names the condition an issuanceRefuseUnusableSession answers.
	sessionShape sessionRefusalShape
}

// clientFlows is which authorization flows a client may use, each as the token endpoint reads it:
// the implicit grant through the client's override and else the global switch, the authorization
// code flow through the client's own flag.
type clientFlows struct {
	implicit bool
	code     bool
}

// issuanceFacts is what decideIssuance decides from. The first six are known from the ceremony and
// the request; every other fact is unknown until Issuance.Run has loaded it, a nil pointer or a false
// loaded flag.
type issuanceFacts struct {
	redirectURI  string
	responseType string
	hintSubject  string
	// authStateGeneration is the generation the ceremony authenticated at, as its context holds it.
	authStateGeneration int64
	// otpClaim is the ceremony's claim to a one-time code, which stands only while the user still
	// has the authenticator it came from (#542).
	otpClaim otpcredential.OTPClaim
	// sessionIdentifierPresent says the request resolved a session identifier.
	sessionIdentifierPresent bool

	registrationLoaded     bool
	registeredRedirectURIs []string
	// clientEnabled is the client's enabled flag, false for a missing client, and is known with the
	// registration.
	clientEnabled bool
	// refusedAdministrativeScopes is the administrative scopes in the scope the issuer would read
	// that the client may not request, none when it may, and is known with the registration (#499).
	refusedAdministrativeScopes []string
	// flows is nil until the client's flows have been loaded.
	flows *clientFlows
	// userLoaded is set once the user has been looked up; user is nil when there is none.
	userLoaded bool
	user       *record.User
	// sessionLoaded is set once the session has been looked up; the two after it are false when
	// there is none. sessionOwned is AuthContext.OwnsSession's answer for it.
	sessionLoaded  bool
	sessionPresent bool
	sessionOwned   bool
	sessionValid   *bool
	effectiveScope *string
}

// decideIssuance decides what /auth/issue does with a ceremony ready to issue, or names the next
// fact it needs to decide that. The checks run in a fixed order and the first that fails is the
// answer, so each fact is asked for only once every check before it has passed:
//
//  1. The redirect URI the ceremony would be answered at is still registered on the client (#241).
//     It is first because every later refusal answers the client by redirect, and a redirect to a
//     callback the operator has removed navigates the browser to that host on a refused request, the
//     harm RFC 9700 section 4.11.2 describes. A missing client has no registrations. Loopback port
//     flexibility (RFC 8252 section 7.3) is the caller's to compute, per urlmatch's package contract
//     (#41), and applies only to the exact response type "code" (IsCodeOnly), so a stored "code code"
//     or "code foo" buys no arbitrary port (#244). Ahead of it, the redirect URI is not plain http
//     off the loopback interface: /auth/authorize refuses such a request, and a ceremony it validated
//     before that refusal existed is stopped here, before anything is minted, on the same page (RFC
//     9700 section 2.6, #590). It names the scheme, so it outranks the client's state.
//  2. The client is still enabled and still allowed the flow the ceremony is for (#197), read as at
//     /auth/authorize: the implicit grant through the client's override and else the global switch.
//     A disabled client is refused on the page /auth/authorize renders for one, never by redirect,
//     because answering the client is what disabling it stops; a flow switched off is
//     unauthorized_client by redirect, as the token endpoint answers it. Last of the client's checks,
//     the scope to be issued names no administrative scope the client may not request, answered
//     invalid_scope by redirect (#499 decision 6). None of these reads the hint, the session or the
//     user.
//  3. An id_token_hint names the ceremony's user. OIDC Core 1.0 section 3.1.2.2: "The Authorization
//     Server MUST NOT reply with an ID Token or Access Token for a different user, even if they have
//     an active session with the Authorization Server." A user who no longer exists is not the
//     hint's either. Completion asks this before it binds anything (#535); this check stays as the
//     last line.
//  4. The ceremony may bind a grant to the browser's session: it exists (#129 decision 6), is the
//     ceremony user's (#133), and is valid (#241), for both flows. An empty identifier is the gone
//     shape: middleware.SessionIdentifier puts an identifier on the request only when its row exists,
//     and a code bound to no session would yield an offline refresh token that outlives a terminated
//     session; implicit tokens bound to none could be ended by no termination (#197). Validity is
//     checked without max_age, which bounds the authentication and was applied at /auth/completed.
//     Both issuers take the session row again in their transactions, which closes the gap between
//     this read and the write (#139).
//  5. The user still exists (a 500 if not), is still enabled (access_denied), and the credential the
//     ceremony authenticated with is still current: the user's authentication generation is the
//     ceremony's, the comparison the token endpoint makes at redemption (#197, #106). A ceremony
//     whose methods name a one-time code needs the authenticator it came from to still be the user's
//     (#542 decision 1). A moved generation or a removed authenticator is an unusable session.
//  6. The user holds at least one of the scopes to be issued, filtered against the live permissions
//     just before anything is minted (#241). The authorization_code grant never consults the
//     permission checker, so this is the last live check a code gets. It comes after the binding
//     check, so a ceremony about to be restarted pays none of it.
func decideIssuance(f issuanceFacts) (issuanceAnswer, issuanceFact) {
	decided := func(outcome issuanceOutcome) (issuanceAnswer, issuanceFact) {
		return issuanceAnswer{outcome: outcome}, issuanceFactNone
	}

	if !f.registrationLoaded {
		return issuanceAnswer{}, issuanceFactRegistration
	}
	if loopback.IsPlainHTTPOff(f.redirectURI) {
		return decided(issuanceRefuseInsecureRedirect)
	}
	rtInfo := protocolvalidation.ParseResponseType(f.responseType)
	allowLoopbackPortFlexibility := rtInfo.IsCodeOnly()
	if !urlmatch.RedirectURIIsRegistered(f.registeredRedirectURIs, f.redirectURI, allowLoopbackPortFlexibility) {
		return decided(issuanceRefuseUnregisteredRedirect)
	}

	if !f.clientEnabled {
		return decided(issuanceRefuseClientDisabled)
	}
	isImplicitFlow := rtInfo.IsImplicitFlow()
	if f.flows == nil {
		return issuanceAnswer{}, issuanceFactFlows
	}
	if isImplicitFlow && !f.flows.implicit {
		return decided(issuanceRefuseImplicitDisabled)
	}
	if !isImplicitFlow && !f.flows.code {
		return decided(issuanceRefuseCodeDisabled)
	}
	if len(f.refusedAdministrativeScopes) > 0 {
		return decided(issuanceRefuseAdministrativeScope)
	}

	if f.hintSubject != "" {
		if !f.userLoaded {
			return issuanceAnswer{}, issuanceFactUser
		}
		if f.user == nil || f.user.Subject != f.hintSubject {
			return decided(issuanceRefuseHintMismatch)
		}
	}

	if f.sessionIdentifierPresent && !f.sessionLoaded {
		return issuanceAnswer{}, issuanceFactSession
	}
	if f.sessionValid == nil {
		return issuanceAnswer{}, issuanceFactSessionValidity
	}
	mayBind := f.sessionOwned && *f.sessionValid
	if !mayBind {
		// The three shapes are mutually exclusive by construction: a row that is absent cannot be
		// foreign, and a foreign one is refused on ownership before its clock is read.
		shape := sessionGone
		switch {
		case f.sessionPresent && !f.sessionOwned:
			shape = sessionForeign
		case f.sessionPresent && !*f.sessionValid:
			shape = sessionExpired
		}
		return issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: shape}, issuanceFactNone
	}

	if !f.userLoaded {
		return issuanceAnswer{}, issuanceFactUser
	}
	if f.user == nil {
		return decided(issuanceUserMissing)
	}
	if !f.user.Enabled {
		return decided(issuanceRefuseUserDisabled)
	}
	if f.user.AuthStateGeneration != f.authStateGeneration {
		return issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionGenerationStale}, issuanceFactNone
	}
	if !f.otpClaim.StandsFor(f.user) {
		return issuanceAnswer{outcome: issuanceRefuseUnusableSession, sessionShape: sessionAuthenticatorRemoved}, issuanceFactNone
	}

	if f.effectiveScope == nil {
		return issuanceAnswer{}, issuanceFactEffectiveScope
	}
	if *f.effectiveScope == "" {
		return decided(issuanceRefuseScopeDenied)
	}

	if isImplicitFlow {
		return decided(issuanceIssueImplicit)
	}
	return decided(issuanceIssueCode)
}

// sessionRefusalShape names which of the five conditions refuseUnusableSession answers: three on the
// session backing a ceremony and two on the credentials it authenticated with. The three session
// conditions are mutually exclusive by construction; the other two are reached only after the
// session has passed all three.
type sessionRefusalShape int

const (
	// sessionGone is a session identifier with no row behind it, or none. What removed the row, a
	// termination, a logout or either reaper, cannot be told from here and is not asked (#139
	// decision 9).
	sessionGone sessionRefusalShape = iota
	// sessionForeign is a row that belongs to a different user than the ceremony's (#133).
	sessionForeign
	// sessionExpired is a row that is owned and is outside its idle timeout or its maximum lifetime
	// (#241).
	sessionExpired
	// sessionGenerationStale is a session that is fine and a credential that is not: the user's
	// authentication generation has moved on since the ceremony authenticated, by a password change
	// or a revocation, so whoever signs in next must prove it again (#197, #106).
	sessionGenerationStale
	// sessionAuthenticatorRemoved is a ceremony whose methods name a one-time code from an
	// authenticator the user no longer has. A removal lowers the user's sessions, and a code issued
	// here would carry the removed authenticator past that lowering (#542 decision 1).
	sessionAuthenticatorRemoved
)
