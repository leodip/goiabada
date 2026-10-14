package authflow

// authorizeFact is a fact decideAuthorizeRoute needs and has not been given. Authorization.Run
// loads it and asks again.
type authorizeFact int

const (
	// authorizeFactNone means the route is decided.
	authorizeFactNone authorizeFact = iota
	// authorizeFactRedirectEmission is RedirectWillBeEmitted's answer for this request.
	authorizeFactRedirectEmission
	// authorizeFactSessionValidity is whether the browser holds a valid session.
	authorizeFactSessionValidity
	// authorizeFactValidation is validateAuthorizeRequest's result.
	authorizeFactValidation
	// authorizeFactSessionUser is the subject and enabled flag of the session's user.
	authorizeFactSessionUser
)

// authorizeRoute is where /auth/authorize sends an authorization request.
type authorizeRoute int

const (
	// authorizeRouteUndecided is returned beside a fact still to load.
	authorizeRouteUndecided authorizeRoute = iota
	// authorizeRouteAnswerNow answers a refused request's client at once.
	authorizeRouteAnswerNow
	// authorizeRoutePark parks a refused request's error and sends the visitor to log in first.
	authorizeRoutePark
	// authorizeRoutePromptNone goes on to silent authentication.
	authorizeRoutePromptNone
	// authorizeRouteForceLogin sends the visitor to log in whatever session it holds: prompt=login,
	// or an id_token_hint naming another user than the session's.
	authorizeRouteForceLogin
	// authorizeRouteDisabledUser answers access_denied for a valid session whose user is disabled.
	authorizeRouteDisabledUser
	// authorizeRouteSSO reuses the valid session.
	authorizeRouteSSO
	// authorizeRouteLevel1 sends a visitor with no valid session to log in.
	authorizeRouteLevel1
)

// authorizeRouteFacts is what decideAuthorizeRoute decides from. The raw prompt tokens are known
// from the start; every other fact is unknown until Authorization.Run has loaded it, a nil pointer
// or a false loaded flag.
type authorizeRouteFacts struct {
	// requestsSilence and requestsLogin are the raw prompt parameter's none and login tokens.
	requestsSilence bool
	requestsLogin   bool

	redirectEmitted *bool
	sessionValid    *bool

	// validated is set once validateAuthorizeRequest has run; the four after it are its result.
	validated   bool
	refused     bool
	promptNone  bool
	promptLogin bool
	hintSubject string

	// sessionUserLoaded is set once the session's user has been loaded; the two after it are ""
	// and false when there is no session.
	sessionUserLoaded  bool
	sessionUserSubject string
	sessionUserEnabled bool
}

// decideAuthorizeRoute decides where an authorization request goes, or names the next fact it needs
// to decide that. It asks for each fact only when the answer turns on it, so a request reads
// nothing its route does not need.
//
// Whether a refused request is answered at once or parked behind a login is the first question,
// asked before the validations run: RFC 9700 4.11.2, "The authorization server MUST always
// authenticate the user first and, with the exception of the silent authentication use case, prompt
// the user for credentials when needed, before redirecting the user." Without it, one link sent to
// a logged-out browser makes this server redirect it to a host the client chose, which is attack 1
// in that section verbatim. Authentication is required before a REDIRECT, and only before a
// redirect, so a refusal is answered at once on any of three clauses:
//
//   - requestsSilence: OIDC Core 3.1.2.3 says the server "MUST NOT interact with the End-User" when
//     prompt=none, which is the exception RFC 9700 names.
//   - a withheld redirect: no redirect leaves this server, so the requirement that governs redirects
//     has nothing to say and the visitor reaches the same refusal page with or without a login
//     (#108's and #122's guards, #213 decision 8).
//   - a valid session without login: a session holder has authenticated already, unless the client
//     asked not to be answered on the strength of one (#213 decision 4).
//
// The clause that reads nothing is asked first, and the session only when the redirect would be
// emitted, so each read is reached only when it decides something. The session read is also the
// one the ordinary path below needs, so a request reads it at most once.
func decideAuthorizeRoute(f authorizeRouteFacts) (authorizeRoute, authorizeFact) {
	if !f.requestsSilence {
		if f.redirectEmitted == nil {
			return authorizeRouteUndecided, authorizeFactRedirectEmission
		}
		if *f.redirectEmitted && !f.requestsLogin && f.sessionValid == nil {
			return authorizeRouteUndecided, authorizeFactSessionValidity
		}
	}

	if !f.validated {
		return authorizeRouteUndecided, authorizeFactValidation
	}

	if f.refused {
		answerNow := f.requestsSilence || !*f.redirectEmitted || (!f.requestsLogin && *f.sessionValid)
		if answerNow {
			return authorizeRouteAnswerNow, authorizeFactNone
		}
		return authorizeRoutePark, authorizeFactNone
	}

	// The validated prompt from here, which for an accepted request holds the same tokens as the raw
	// one.
	if f.promptNone {
		return authorizeRoutePromptNone, authorizeFactNone
	}
	// prompt=login skips the session entirely.
	if f.promptLogin {
		return authorizeRouteForceLogin, authorizeFactNone
	}

	if f.sessionValid == nil {
		return authorizeRouteUndecided, authorizeFactSessionValidity
	}
	if !f.sessionUserLoaded {
		return authorizeRouteUndecided, authorizeFactSessionUser
	}

	if !*f.sessionValid {
		return authorizeRouteLevel1, authorizeFactNone
	}
	// OIDC Core 3.1.2.1: a hint naming a different user than the session's forces
	// re-authentication rather than SSO.
	if f.hintSubject != "" && f.sessionUserSubject != f.hintSubject {
		return authorizeRouteForceLogin, authorizeFactNone
	}
	if !f.sessionUserEnabled {
		return authorizeRouteDisabledUser, authorizeFactNone
	}
	return authorizeRouteSSO, authorizeFactNone
}
