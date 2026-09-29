package handlers

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/i18n"
)

// ceremonyIdField is the hidden form field naming the authorization ceremony, and its name is
// duplicated in the auth-flow templates because a template cannot read a Go constant. A rename
// in one place alone renders a form whose every submission is refused, which the integration
// cases catch: they read the field out of the rendered page rather than building the form.
const ceremonyIdField = "ceremonyId"

// ceremonyIdLength matches the length of the continuation id emaillinks issues, and for the
// same reason that package's own comment gives: over the 65-character alphabet
// GenerateSecurityRandomString draws from, this is far more entropy than the value needs. Nobody outside the session ever sees it and it authorizes
// nothing on its own.
const ceremonyIdLength = 32

// ceremonyMatches reports whether a submitted form belongs to the ceremony the session
// currently holds.
//
// An empty stored id is refused rather than matched against an empty submission. Only an auth
// context written by a binary from before #79 can carry one, and treating "" as equal to ""
// would make such a context accept a form naming no ceremony at all, which is every forged
// form. The cost is that a user mid-flow across a deploy is refused once and starts the
// authorization again.
//
// Constant time, like forgotPasswordCodeMatches and the client secret comparison in
// protocolvalidation.ValidateTokenRequest. Not because this value is guessed at, but because a
// plain comparison stopping at the first differing byte is the kind of thing that is cheap to avoid
// and expensive to notice later.
func ceremonyMatches(contextCeremonyId string, submitted string) bool {
	if contextCeremonyId == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(contextCeremonyId), []byte(submitted)) == 1
}

// rejectCeremonyMismatch answers a submission that names a ceremony the session no longer
// holds: audit it, then render the error page at 400.
//
// The auth context is deliberately NOT touched. The ceremony that is current is the one the
// user is actually working on, in another tab, and clearing or advancing it here would let a
// forgotten tab cancel a live authorization with nothing left to recover from. The stale form
// is simply dead. The client is not told either, for the same reason: the client that would
// receive an error is the current one, whose authorization the user still wants (#79
// decision 5).
//
// Mirrors accounthandlers' rejectResetPassword: audit, then render, at http.StatusBadRequest because a
// submission was genuinely refused.
func rejectCeremonyMismatch(pageRenderer PageRenderer, auditLogger AuditLogger, w http.ResponseWriter,
	r *http.Request, authContext *ceremony.AuthContext) {

	const maxAuditedValueLength = 100

	// Truncated for the same reason accounthandlers' auditedClientIP truncates it for the two
	// emailed-link flows: MiddlewareRealIP resolves the IP from a forwarded header in a proxied
	// deployment, so this is a sink for a value that originates outside the process.
	clientIP := middleware.GetClientIPFromRequest(r)
	if len(clientIP) > maxAuditedValueLength {
		clientIP = clientIP[:maxAuditedValueLength]
	}

	details := map[string]interface{}{
		"clientId":  authContext.ClientId,
		"authState": string(authContext.AuthState),
		"ipAddress": clientIP,
	}
	// Absent rather than zero when the ceremony has not identified anyone yet, which is every
	// submission of the password form. A payload naming user 0 asserts a row that does not exist.
	if authContext.UserId != 0 {
		details["userId"] = authContext.UserId
	}
	auditLogger.Log(r.Context(), audit.AuditAuthCeremonyMismatch, details)

	bind := map[string]interface{}{
		"title":       i18n.T(r.Context(), "auth_error.ceremony_mismatch.title"),
		"error":       i18n.T(r.Context(), "auth_error.ceremony_mismatch.message"),
		"_httpStatus": http.StatusBadRequest,
	}

	if err := pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind); err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
}

// loadAuthContext reads the ceremony's auth context for a gated route, and answers the request
// itself when there is none to read: a missing context redirects to the account page with a warn
// line, since a visitor who reaches a step after the ceremony ended has nothing to resume and
// somewhere better to be, and any other failure is a 500. It reports false when it answered, and the
// caller then returns without writing anything.
//
// It stops at loading. The three form posts check the submitted ceremony id between this and
// requireAuthState, which is why the two are separate helpers rather than one (#436 decision 5).
func loadAuthContext(pageRenderer PageRenderer, ceremonyStore CeremonyStore, w http.ResponseWriter,
	r *http.Request, adminConsoleBaseURL string) (*ceremony.AuthContext, bool) {

	authContext, err := ceremonyStore.GetAuthContext(r)
	if err != nil {
		if errors.Is(err, ceremony.ErrNoAuthContext) {
			var profileUrl = profileURL(adminConsoleBaseURL)
			slog.WarnContext(r.Context(), "auth context is missing, redirecting", "redirect", profileUrl)
			http.Redirect(w, r, profileUrl, http.StatusFound)
		} else {
			pageRenderer.InternalServerError(w, r, err)
		}
		return nil, false
	}
	return authContext, true
}

// requireAuthState is every gated route's check that the ceremony is on a step the route accepts.
// When it is not, it renders the error page at 400, logs the accepted states and the actual one at
// warn, and reports false; the caller then returns without writing anything.
//
// A mismatch is a client's mistake and not a server fault. The ordinary way to reach one is the Back
// button: the browser returns to /auth/pwd after the password was accepted, the context has moved on
// to level1_password_completed, and a 500 page with a stack would tell the visitor the server had
// broken. RFC 9110 section 15.5.1 is the fit, "the server cannot or will not process the request due
// to something that is perceived to be a client error"; 15.6.1's 500 is for "an unexpected
// condition", and a stale tab is not unexpected (#279 decision 21, #248 part 1). Every route answers
// through here, /auth/level1completed with its two accepted states included, so no gate can drift
// back to a 500 on its own (#436).
//
// warn rather than error, and with both sides named: the pair is the whole diagnosis, and an
// operator watching error-level lines should not be paged by a Back button. There is no stack
// because there is no failure to trace to a line of code.
//
// The auth context is deliberately NOT touched, for rejectCeremonyMismatch's reason: the state it
// holds belongs to the step the user is actually on, and advancing or clearing it here would let a
// stale page cancel a live authorization. The client is not told either, for the same reason.
func requireAuthState(pageRenderer PageRenderer, w http.ResponseWriter, r *http.Request,
	authContext *ceremony.AuthContext, accepted ...ceremony.AuthState) bool {

	if authContext.InState(accepted...) {
		return true
	}

	acceptedStates := make([]string, len(accepted))
	for i, state := range accepted {
		acceptedStates[i] = string(state)
	}
	slog.WarnContext(r.Context(), "auth state mismatch, refusing the request",
		"accepted_states", acceptedStates, "actual_state", string(authContext.AuthState))

	bind := map[string]interface{}{
		"title":       i18n.T(r.Context(), "auth_error.state_mismatch.title"),
		"error":       i18n.T(r.Context(), "auth_error.state_mismatch.message"),
		"_httpStatus": http.StatusBadRequest,
	}

	if err := pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind); err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
	return false
}
